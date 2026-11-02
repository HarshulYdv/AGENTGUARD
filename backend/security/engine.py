"""PolicyEngine — deterministic rule evaluation for agent actions.

Every proposed action is checked against the task's security context
using a fixed chain of rules. No LLM or probabilistic reasoning is
involved. The engine returns a fully auditable ``PolicyDecision``.

Security invariants enforced by this module:
  • A missing or invalid task context is always BLOCK.
  • A missing approval is never interpreted as approval.
  • Agent-provided claims about authorization or approval are untrusted.
  • Approvals must be verified against an authoritative human approval record.
  • An agent cannot modify its own task permissions or security contexts.
  • Denied actions always take precedence over allowed actions.
  • Monetary amounts must be strictly non-negative, finite numbers (no NaN, inf, or negative).
  • Deterministic rule evaluation only — no non-deterministic model calls.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple, Union

from backend.core.logging import get_logger
from backend.security.context import TaskContextManager
from backend.security.models import (
    Action,
    ActionType,
    ApprovalRecord,
    ApprovalRequirement,
    Policy,
    PolicyDecision,
    PolicyRule,
    PolicyRuleType,
    Severity,
    TaskContext,
    TaskStatus,
    Verdict,
)

logger = get_logger("security.engine")


# ── Built-in rule catalogue ───────────────────────────────────────────────

_RULE_TASK_STATUS = PolicyRule(
    rule_id="builtin-task-status",
    rule_type=PolicyRuleType.TASK_STATUS,
    description="Reject actions when the task is not in ACTIVE status.",
    severity=Severity.CRITICAL,
)

_RULE_TASK_EXPIRATION = PolicyRule(
    rule_id="builtin-task-expiration",
    rule_type=PolicyRuleType.TASK_EXPIRATION,
    description="Reject actions on expired tasks.",
    severity=Severity.HIGH,
)

_RULE_SELF_MODIFICATION = PolicyRule(
    rule_id="builtin-prevent-self-modification",
    rule_type=PolicyRuleType.SELF_MODIFICATION,
    description="Prohibit agents from modifying their own task permissions or security contexts.",
    severity=Severity.CRITICAL,
)

_RULE_ACTION_DENIED = PolicyRule(
    rule_id="builtin-action-denied",
    rule_type=PolicyRuleType.ACTION_PERMISSION,
    description="Reject actions explicitly listed in denied_actions.",
    severity=Severity.HIGH,
)

_RULE_ACTION_ALLOWED = PolicyRule(
    rule_id="builtin-action-allowed",
    rule_type=PolicyRuleType.ACTION_PERMISSION,
    description="Reject actions not present in the allowed_actions whitelist.",
    severity=Severity.HIGH,
)

_RULE_ENTITY_RESTRICTED = PolicyRule(
    rule_id="builtin-entity-restricted",
    rule_type=PolicyRuleType.ENTITY_RESTRICTION,
    description="Reject actions targeting a restricted entity.",
    severity=Severity.CRITICAL,
)

_RULE_ENTITY_ALLOWED = PolicyRule(
    rule_id="builtin-entity-allowed",
    rule_type=PolicyRuleType.ENTITY_RESTRICTION,
    description="Reject actions targeting an entity not in the allowed list.",
    severity=Severity.MEDIUM,
)

_RULE_TRANSACTION_LIMIT = PolicyRule(
    rule_id="builtin-transaction-limit",
    rule_type=PolicyRuleType.TRANSACTION_LIMIT,
    description="Reject actions whose amount is invalid, negative, NaN, infinite, or exceeds the configured limit.",
    severity=Severity.HIGH,
)

_RULE_APPROVAL_GATE = PolicyRule(
    rule_id="builtin-approval-gate",
    rule_type=PolicyRuleType.APPROVAL_GATE,
    description="Require verified human approval from an authoritative approval record.",
    severity=Severity.MEDIUM,
)


def _parse_and_validate_amount(value: Any) -> Tuple[Optional[float], Optional[str]]:
    """Strictly validate and parse a monetary amount parameter.

    Returns:
        (parsed_float, None) on success
        (None, error_description) on failure (e.g. NaN, inf, negative, unparseable)
    """
    if value is None:
        return None, None

    try:
        val = float(value)
    except (TypeError, ValueError):
        return None, f"Amount '{value}' cannot be converted to a valid number."

    if math.isnan(val):
        return None, "Amount cannot be NaN (Not a Number)."
    if math.isinf(val):
        return None, "Amount cannot be infinite."
    if val < 0.0:
        return None, f"Negative amounts ({val}) are strictly prohibited."

    return val, None


class PolicyEngine:
    """Evaluate proposed actions against a task context's security boundaries.

    The engine runs a deterministic chain of checks in priority order.
    The first failing check short-circuits with a BLOCK verdict. If all
    hard checks pass, approval gates may escalate the decision to
    REQUIRE_APPROVAL. Only when every check passes is the verdict ALLOW.
    """

    def __init__(
        self,
        context_manager: TaskContextManager,
        *,
        policy: Optional[Union[Policy, List[PolicyRule]]] = None,
    ) -> None:
        self._ctx_mgr = context_manager
        if isinstance(policy, Policy):
            self._policy = policy
            self._custom_rules = [r for r in policy.rules if r.enabled]
        elif isinstance(policy, list):
            self._policy = Policy(rules=policy)
            self._custom_rules = [r for r in policy if r.enabled]
        else:
            self._policy = Policy()
            self._custom_rules = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, action: Action) -> PolicyDecision:
        """Return an auditable decision for *action*.

        The evaluation order is:
        1. Action integrity & task existence
        2. Target entity validity
        3. Task status & expiration check
        4. Self-modification guard
        5. Denied-action blacklist
        6. Allowed-action whitelist
        7. Restricted-entity blacklist
        8. Allowed-entity whitelist
        9. Transaction limits & monetary validation
        10. Trusted approval verification
        11. Default ALLOW
        """
        # ── 1. Action integrity & Task existence ──────────────────────
        if action is None or not isinstance(action, Action):
            return PolicyDecision(
                action_id=getattr(action, "action_id", "malformed"),
                task_id=getattr(action, "task_id", "malformed"),
                verdict=Verdict.BLOCK,
                rule_id="builtin-malformed-action",
                reason="Action payload is missing or malformed.",
                severity=Severity.CRITICAL,
                evaluated_constraints={"action_type": str(type(action))},
            )

        if not action.task_id or not isinstance(action.task_id, str) or not action.task_id.strip():
            return self._block(
                action=action,
                task_id=str(action.task_id or ""),
                rule=PolicyRule(
                    rule_id="builtin-task-missing",
                    rule_type=PolicyRuleType.TASK_SCOPE,
                    description="No task context found for invalid task_id.",
                    severity=Severity.CRITICAL,
                ),
                reason="Task ID is empty or invalid. Actions without a valid security context are rejected.",
                constraints={"task_id": action.task_id, "context_found": False},
            )

        context = self._ctx_mgr.get_task(action.task_id.strip())

        if context is None:
            return self._block(
                action=action,
                task_id=action.task_id,
                rule=PolicyRule(
                    rule_id="builtin-task-missing",
                    rule_type=PolicyRuleType.TASK_SCOPE,
                    description="No task context found for the given task_id.",
                    severity=Severity.CRITICAL,
                ),
                reason=(
                    f"No task context registered for task_id '{action.task_id}'. "
                    "Actions without a valid security context are rejected."
                ),
                constraints={"task_id": action.task_id, "context_found": False},
            )

        # ── 2. Target entity validity ─────────────────────────────────
        if not action.target_entity or not isinstance(action.target_entity, str) or not action.target_entity.strip():
            return self._block(
                action=action,
                task_id=context.task_id,
                rule=PolicyRule(
                    rule_id="builtin-invalid-target-entity",
                    rule_type=PolicyRuleType.ENTITY_RESTRICTION,
                    description="Target entity must be a valid, non-empty identifier.",
                    severity=Severity.HIGH,
                ),
                reason="Target entity is missing, empty, or whitespace. Malformed actions are rejected.",
                constraints={"target_entity": action.target_entity},
            )

        # ── 3. Task status & Expiration check ─────────────────────────
        if context.task_status == TaskStatus.EXPIRED:
            return self._block(
                action=action,
                task_id=context.task_id,
                rule=_RULE_TASK_EXPIRATION,
                reason=(
                    f"Task '{context.task_id}' expired at "
                    f"{(context.expiration_time.isoformat() if context.expiration_time else 'unknown')}. "
                    "Actions on expired tasks are rejected."
                ),
                constraints={
                    "task_status": context.task_status.value,
                    "expiration_time": (
                        context.expiration_time.isoformat()
                        if context.expiration_time
                        else None
                    ),
                },
            )

        if context.task_status == TaskStatus.COMPLETED:
            return self._block(
                action=action,
                task_id=context.task_id,
                rule=_RULE_TASK_STATUS,
                reason=(
                    f"Task '{context.task_id}' is in 'completed' status. "
                    "Completed tasks cannot execute further actions."
                ),
                constraints={
                    "task_status": context.task_status.value,
                    "required_status": TaskStatus.ACTIVE.value,
                },
            )

        if context.task_status != TaskStatus.ACTIVE:
            return self._block(
                action=action,
                task_id=context.task_id,
                rule=_RULE_TASK_STATUS,
                reason=(
                    f"Task '{context.task_id}' is in "
                    f"'{context.task_status.value}' status. "
                    "Only ACTIVE tasks may execute actions."
                ),
                constraints={
                    "task_status": context.task_status.value,
                    "required_status": TaskStatus.ACTIVE.value,
                },
            )

        # Expiration clock check
        decision = self._check_expiration(action, context)
        if decision is not None:
            return decision

        # ── 4. Self-modification guard ────────────────────────────────
        decision = self._check_self_modification(action, context)
        if decision is not None:
            return decision

        # ── 5. Denied-action blacklist ────────────────────────────────
        decision = self._check_denied_actions(action, context)
        if decision is not None:
            return decision

        # ── 6. Allowed-action whitelist ───────────────────────────────
        decision = self._check_allowed_actions(action, context)
        if decision is not None:
            return decision

        # ── 7. Restricted-entity blacklist ────────────────────────────
        decision = self._check_restricted_entities(action, context)
        if decision is not None:
            return decision

        # ── 8. Allowed-entity whitelist ───────────────────────────────
        decision = self._check_allowed_entities(action, context)
        if decision is not None:
            return decision

        # ── 9. Transaction limits & monetary validation ───────────────
        decision = self._check_transaction_limits(action, context)
        if decision is not None:
            return decision

        # ── 10. Approval gates & verified approvals ───────────────────
        decision = self._check_approval_gates(action, context)
        if decision is not None:
            return decision

        # ── 11. Default ALLOW ─────────────────────────────────────────
        return self._allow(action, context)

    # ------------------------------------------------------------------
    # Individual rule checks (private)
    # ------------------------------------------------------------------

    def _check_expiration(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        if ctx.expiration_time is None:
            return None
        now = datetime.now(timezone.utc)
        if now >= ctx.expiration_time:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_TASK_EXPIRATION,
                reason=(
                    f"Task '{ctx.task_id}' expired at "
                    f"{ctx.expiration_time.isoformat()}. "
                    f"Current time: {now.isoformat()}."
                ),
                constraints={
                    "expiration_time": ctx.expiration_time.isoformat(),
                    "current_time": now.isoformat(),
                },
            )
        return None

    def _check_self_modification(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        """Prevent an agent from modifying security contexts or permissions."""
        target_lower = action.target_entity.strip().lower()
        forbidden_targets = {
            "task_context",
            "security_context",
            "task_permissions",
            "security_policy",
            "guardrail_policy",
            f"task_context:{ctx.task_id.lower()}",
        }

        attempts_permission_escalation = (
            target_lower in forbidden_targets
            or action.parameters.get("modify_permissions") is True
            or action.parameters.get("escalate_privilege") is True
            or action.parameters.get("override_policy") is True
        )

        if attempts_permission_escalation:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_SELF_MODIFICATION,
                reason=(
                    f"Action targets security boundary '{action.target_entity}'. "
                    "Agents are strictly forbidden from modifying task permissions or policies."
                ),
                constraints={
                    "target_entity": action.target_entity,
                    "requested_by": action.requested_by,
                },
            )
        return None

    def _check_denied_actions(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        if action.action_type in ctx.denied_actions:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_ACTION_DENIED,
                reason=(
                    f"Action type '{action.action_type.value}' is explicitly "
                    f"denied for task '{ctx.task_id}'."
                ),
                constraints={
                    "denied_actions": [a.value for a in ctx.denied_actions],
                    "requested_action": action.action_type.value,
                },
            )
        return None

    def _check_allowed_actions(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        if ctx.allowed_actions and action.action_type not in ctx.allowed_actions:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_ACTION_ALLOWED,
                reason=(
                    f"Action type '{action.action_type.value}' is not in the "
                    f"allowed actions whitelist for task '{ctx.task_id}'."
                ),
                constraints={
                    "allowed_actions": [a.value for a in ctx.allowed_actions],
                    "requested_action": action.action_type.value,
                },
            )
        return None

    def _check_restricted_entities(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        if action.target_entity in ctx.restricted_entities:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_ENTITY_RESTRICTED,
                reason=(
                    f"Entity '{action.target_entity}' is restricted "
                    f"for task '{ctx.task_id}'."
                ),
                constraints={
                    "restricted_entities": ctx.restricted_entities,
                    "target_entity": action.target_entity,
                },
            )
        return None

    def _check_allowed_entities(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        if ctx.allowed_entities and action.target_entity not in ctx.allowed_entities:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_ENTITY_ALLOWED,
                reason=(
                    f"Entity '{action.target_entity}' is not in the "
                    f"allowed entities list for task '{ctx.task_id}'."
                ),
                constraints={
                    "allowed_entities": ctx.allowed_entities,
                    "target_entity": action.target_entity,
                },
            )
        return None

    def _check_transaction_limits(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        action_key = action.action_type.value
        limit = ctx.transaction_limits.get(action_key)
        amount_raw = action.parameters.get("amount")

        # If a transaction limit is configured for this action type, 'amount' must be provided
        if limit is not None and amount_raw is None:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_TRANSACTION_LIMIT,
                reason=(
                    f"Action type '{action_key}' has a transaction limit of {limit}, "
                    "but no 'amount' parameter was provided."
                ),
                constraints={
                    "transaction_limit": limit,
                    "action_type": action_key,
                    "amount": None,
                },
            )

        if amount_raw is None:
            return None

        amount_float, err = _parse_and_validate_amount(amount_raw)
        if err is not None:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_TRANSACTION_LIMIT,
                reason=f"Invalid monetary amount: {err}",
                constraints={"amount": str(amount_raw), "validation_error": err},
            )

        assert amount_float is not None

        action_key = action.action_type.value
        limit = ctx.transaction_limits.get(action_key)
        if limit is not None and amount_float > limit:
            return self._block(
                action=action,
                task_id=ctx.task_id,
                rule=_RULE_TRANSACTION_LIMIT,
                reason=(
                    f"Transaction amount {amount_float} exceeds the "
                    f"limit of {limit} for action type '{action_key}' "
                    f"on task '{ctx.task_id}'."
                ),
                constraints={
                    "transaction_limit": limit,
                    "requested_amount": amount_float,
                    "action_type": action_key,
                },
            )
        return None

    def _check_approval_gates(
        self, action: Action, ctx: TaskContext
    ) -> Optional[PolicyDecision]:
        for requirement in ctx.approval_requirements:
            if action.action_type not in requirement.action_types:
                continue

            # Check amount threshold if specified
            if requirement.min_amount is not None:
                amount_raw = action.parameters.get("amount")
                if amount_raw is not None:
                    amount_float, err = _parse_and_validate_amount(amount_raw)
                    if err is not None:
                        return self._block(
                            action=action,
                            task_id=ctx.task_id,
                            rule=_RULE_TRANSACTION_LIMIT,
                            reason=f"Invalid monetary amount in approval evaluation: {err}",
                            constraints={"amount": str(amount_raw), "validation_error": err},
                        )
                    assert amount_float is not None
                    if amount_float < requirement.min_amount:
                        continue  # Below threshold — gate not triggered

            # Gate is triggered.
            #
            # SECURITY INVARIANT 1:
            # An agent cannot forge approval by setting approval_granted=True
            # or approved_by="supervisor" in its own action parameters.
            # Any unverified approval claims are untrusted.
            #
            # SECURITY INVARIANT 2:
            # Approvals must be backed by an authoritative ApprovalRecord in the
            # trusted store.
            approval_id = action.parameters.get("approval_id")

            if not approval_id:
                # Agent provided no approval_id (or tried to forge with parameters alone)
                forged_claim = bool(action.parameters.get("approval_granted") or action.parameters.get("approved_by"))
                reason_suffix = (
                    " Unverified approval claims in action parameters are untrusted."
                    if forged_claim
                    else ""
                )
                return PolicyDecision(
                    action_id=action.action_id,
                    task_id=ctx.task_id,
                    verdict=Verdict.REQUIRE_APPROVAL,
                    rule_id=_RULE_APPROVAL_GATE.rule_id,
                    reason=(
                        f"Action type '{action.action_type.value}' requires explicit human approval "
                        f"from one of: {requirement.approver_roles}.{reason_suffix}"
                    ),
                    severity=_RULE_APPROVAL_GATE.severity,
                    evaluated_constraints={
                        "required_approver_roles": requirement.approver_roles,
                        "approval_id_provided": False,
                        "forged_claim_detected": forged_claim,
                        "action_type": action.action_type.value,
                    },
                )

            # Retrieve authoritative approval from trusted registry
            trusted_approval = self._ctx_mgr.get_approval(str(approval_id))

            if trusted_approval is None:
                return PolicyDecision(
                    action_id=action.action_id,
                    task_id=ctx.task_id,
                    verdict=Verdict.REQUIRE_APPROVAL,
                    rule_id=_RULE_APPROVAL_GATE.rule_id,
                    reason=(
                        f"Approval ID '{approval_id}' was not found in the trusted approval store. "
                        "Unverified approval IDs are rejected."
                    ),
                    severity=_RULE_APPROVAL_GATE.severity,
                    evaluated_constraints={
                        "approval_id": str(approval_id),
                        "registered": False,
                        "required_approver_roles": requirement.approver_roles,
                    },
                )

            if not trusted_approval.valid:
                return PolicyDecision(
                    action_id=action.action_id,
                    task_id=ctx.task_id,
                    verdict=Verdict.REQUIRE_APPROVAL,
                    rule_id=_RULE_APPROVAL_GATE.rule_id,
                    reason=f"Approval ID '{approval_id}' has been revoked or invalidated.",
                    severity=_RULE_APPROVAL_GATE.severity,
                    evaluated_constraints={
                        "approval_id": str(approval_id),
                        "valid": False,
                    },
                )

            # Cross-task replay prevention
            if trusted_approval.task_id != ctx.task_id:
                return self._block(
                    action=action,
                    task_id=ctx.task_id,
                    rule=_RULE_APPROVAL_GATE,
                    reason=(
                        f"Approval ID '{approval_id}' belongs to task '{trusted_approval.task_id}', "
                        f"not '{ctx.task_id}'. Cross-task approval replay attack blocked."
                    ),
                    constraints={
                        "approval_id": str(approval_id),
                        "approval_task_id": trusted_approval.task_id,
                        "action_task_id": ctx.task_id,
                    },
                )

            # Action type mismatch prevention
            if trusted_approval.action_type != action.action_type:
                return self._block(
                    action=action,
                    task_id=ctx.task_id,
                    rule=_RULE_APPROVAL_GATE,
                    reason=(
                        f"Approval ID '{approval_id}' was issued for action '{trusted_approval.action_type.value}', "
                        f"not requested action '{action.action_type.value}'."
                    ),
                    constraints={
                        "approved_action_type": trusted_approval.action_type.value,
                        "requested_action_type": action.action_type.value,
                    },
                )

            # Target entity mismatch prevention (if specific entity was approved)
            if trusted_approval.target_entity and trusted_approval.target_entity != action.target_entity:
                return self._block(
                    action=action,
                    task_id=ctx.task_id,
                    rule=_RULE_APPROVAL_GATE,
                    reason=(
                        f"Approval ID '{approval_id}' was issued for entity '{trusted_approval.target_entity}', "
                        f"not requested entity '{action.target_entity}'."
                    ),
                    constraints={
                        "approved_entity": trusted_approval.target_entity,
                        "requested_entity": action.target_entity,
                    },
                )

            # Maximum approved amount ceiling verification
            if trusted_approval.max_approved_amount is not None:
                amount_raw = action.parameters.get("amount")
                if amount_raw is None:
                    return self._block(
                        action=action,
                        task_id=ctx.task_id,
                        rule=_RULE_APPROVAL_GATE,
                        reason=(
                            f"Action '{action.action_id}' omitted monetary amount, but approval "
                            f"'{approval_id}' is bounded to a maximum amount of {trusted_approval.max_approved_amount}."
                        ),
                        constraints={
                            "approval_id": str(approval_id),
                            "max_approved_amount": trusted_approval.max_approved_amount,
                            "requested_amount": None,
                        },
                    )

                amount_float, err = _parse_and_validate_amount(amount_raw)
                if err is not None:
                    return self._block(
                        action=action,
                        task_id=ctx.task_id,
                        rule=_RULE_TRANSACTION_LIMIT,
                        reason=f"Invalid monetary amount in approval evaluation: {err}",
                        constraints={"amount": str(amount_raw), "validation_error": err},
                    )
                if amount_float is not None and amount_float > trusted_approval.max_approved_amount:
                    return self._block(
                        action=action,
                        task_id=ctx.task_id,
                        rule=_RULE_APPROVAL_GATE,
                        reason=(
                            f"Transaction amount {amount_float} exceeds the maximum amount of "
                            f"{trusted_approval.max_approved_amount} authorized under approval '{approval_id}'."
                        ),
                        constraints={
                            "approval_id": str(approval_id),
                            "max_approved_amount": trusted_approval.max_approved_amount,
                            "requested_amount": amount_float,
                        },
                    )

            # Approver role verification
            if trusted_approval.approver_role not in requirement.approver_roles:
                return PolicyDecision(
                    action_id=action.action_id,
                    task_id=ctx.task_id,
                    verdict=Verdict.REQUIRE_APPROVAL,
                    rule_id=_RULE_APPROVAL_GATE.rule_id,
                    reason=(
                        f"Approver '{trusted_approval.approved_by}' holds role '{trusted_approval.approver_role}', "
                        f"which is not authorized for this action. Required: {requirement.approver_roles}."
                    ),
                    severity=_RULE_APPROVAL_GATE.severity,
                    evaluated_constraints={
                        "required_approver_roles": requirement.approver_roles,
                        "actual_approver_role": trusted_approval.approver_role,
                        "approved_by": trusted_approval.approved_by,
                    },
                )

            # Reject agent self-approval
            if trusted_approval.approved_by.lower() == "agent":
                return self._block(
                    action=action,
                    task_id=ctx.task_id,
                    rule=_RULE_APPROVAL_GATE,
                    reason="Agent attempted self-approval. Human supervisor approval is strictly required.",
                    constraints={"approved_by": trusted_approval.approved_by},
                )

        return None

    # ------------------------------------------------------------------
    # Decision builders
    # ------------------------------------------------------------------

    def _block(
        self,
        *,
        action: Action,
        task_id: str,
        rule: PolicyRule,
        reason: str,
        constraints: dict,
    ) -> PolicyDecision:
        logger.warning(
            f"BLOCK action '{action.action_id}' on task '{task_id}': {reason}"
        )
        return PolicyDecision(
            action_id=action.action_id,
            task_id=task_id,
            verdict=Verdict.BLOCK,
            rule_id=rule.rule_id,
            reason=reason,
            severity=rule.severity,
            evaluated_constraints=constraints,
        )

    def _allow(self, action: Action, ctx: TaskContext) -> PolicyDecision:
        logger.info(
            f"ALLOW action '{action.action_id}' "
            f"({action.action_type.value}) on task '{ctx.task_id}'."
        )
        return PolicyDecision(
            action_id=action.action_id,
            task_id=ctx.task_id,
            verdict=Verdict.ALLOW,
            rule_id="builtin-default-allow",
            reason="All policy checks passed.",
            severity=Severity.LOW,
            evaluated_constraints={
                "allowed_actions": [a.value for a in ctx.allowed_actions],
                "allowed_entities": ctx.allowed_entities,
                "action_type": action.action_type.value,
                "target_entity": action.target_entity,
            },
        )
