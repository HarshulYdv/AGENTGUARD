"""Unit and integration tests for PolicyEngine and Security Audit checks.

Covers all required security invariants and verification scenarios:
  1. Authorized invoice reading -> ALLOW
  2. Unauthorized action -> BLOCK
  3. Unauthorized beneficiary -> BLOCK
  4. Transaction exceeding limit -> BLOCK
  5. Missing human approval -> REQUIRE_APPROVAL
  6. Expired task -> BLOCK
  7. Revoked task -> BLOCK
  8. Invalid task context -> BLOCK
  Security Audit Check 1: Approval forgery prevention (agent claims approval in parameters)
  Security Audit Check 2: Authoritative approval registry verification (valid, invalid role, revoked, replay)
  Security Audit Check 3 & 5: Self-modification attempt & immutability
  Security Audit Check 4: Completed task execution prevention
  Security Audit Check 6: Monetary validation (negative, NaN, inf, -inf, malformed string)
  Security Audit Check 7: Malformed action parameters (empty target entity, whitespace)
  Security Audit Check 8: Missing or malformed security contexts (empty task_id, whitespace, None action)
"""

from datetime import datetime, timedelta, timezone
import pytest

from backend.security.context import TaskContextManager
from backend.security.engine import PolicyEngine
from backend.security.models import (
    Action,
    ActionType,
    ApprovalRecord,
    ApprovalRequirement,
    Policy,
    PolicyRule,
    PolicyRuleType,
    Severity,
    TaskContext,
    TaskStatus,
    Verdict,
)


@pytest.fixture
def context_manager() -> TaskContextManager:
    """Provide a fresh TaskContextManager."""
    return TaskContextManager()


@pytest.fixture
def engine(context_manager: TaskContextManager) -> PolicyEngine:
    """Provide a PolicyEngine wired to the fresh context manager."""
    return PolicyEngine(context_manager=context_manager)


@pytest.fixture
def standard_task(context_manager: TaskContextManager) -> TaskContext:
    """Register a standard invoice & payment task context."""
    task = TaskContext(
        task_id="task-invoice-finance-001",
        original_instruction="Read vendor invoices and transfer payments up to $10,000 for approved ACME entities.",
        task_status=TaskStatus.ACTIVE,
        creation_time=datetime.now(timezone.utc),
        expiration_time=datetime.now(timezone.utc) + timedelta(hours=2),
        allowed_actions=[ActionType.READ, ActionType.TRANSFER],
        denied_actions=[ActionType.DELETE],
        allowed_entities=["invoice:acme-101", "invoice:acme-102", "vendor:acme-corp"],
        restricted_entities=["vendor:sanctioned-entity", "account:unauthorized-offshore"],
        transaction_limits={"transfer": 10000.0},
        approval_requirements=[
            ApprovalRequirement(
                action_types=[ActionType.TRANSFER],
                min_amount=5000.0,
                approver_roles=["finance_director", "supervisor"],
            )
        ],
        metadata={"department": "Accounts Payable"},
    )
    return context_manager.create_task(task)


# ==============================================================================
# 1. Authorized Invoice Reading
# ==============================================================================

def test_authorized_invoice_reading(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 1: Agent reads an authorized invoice within task boundaries."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
        parameters={"format": "pdf"},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.ALLOW
    assert decision.action_id == action.action_id
    assert decision.task_id == standard_task.task_id
    assert decision.severity == Severity.LOW
    assert "All policy checks passed" in decision.reason
    assert decision.evaluated_constraints["action_type"] == "read"
    assert decision.evaluated_constraints["target_entity"] == "invoice:acme-101"


# ==============================================================================
# 2. Unauthorized Action
# ==============================================================================

def test_unauthorized_action_not_allowed(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 2a: Agent attempts an action not in the allowed_actions whitelist."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.WRITE,
        target_entity="invoice:acme-101",
        parameters={"notes": "Tampering attempt"},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-action-allowed"
    assert decision.severity == Severity.HIGH
    assert "not in the allowed actions whitelist" in decision.reason


def test_unauthorized_action_explicitly_denied(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 2b: Agent attempts an action explicitly listed in denied_actions."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.DELETE,
        target_entity="invoice:acme-101",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-action-denied"
    assert decision.severity == Severity.HIGH
    assert "explicitly denied" in decision.reason


# ==============================================================================
# 3. Unauthorized Beneficiary
# ==============================================================================

def test_unauthorized_beneficiary_not_in_allowed_entities(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 3a: Agent attempts to interact with an entity outside allowed_entities."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:stranger-999",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-entity-allowed"
    assert "not in the allowed entities list" in decision.reason


def test_unauthorized_beneficiary_restricted_entity(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 3b: Agent attempts a transaction targeting an explicitly restricted entity."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:sanctioned-entity",
        parameters={"amount": 1000.0},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-entity-restricted"
    assert decision.severity == Severity.CRITICAL
    assert "is restricted" in decision.reason


# ==============================================================================
# 4. Transaction Exceeding Limit
# ==============================================================================

def test_transaction_exceeding_limit(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 4: Agent requests a monetary transfer exceeding the task limit ($10,000)."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 25000.0},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-transaction-limit"
    assert decision.severity == Severity.HIGH
    assert "exceeds the limit of 10000.0" in decision.reason
    assert decision.evaluated_constraints["requested_amount"] == 25000.0


# ==============================================================================
# 5. Human Approval Verification & Forgery Defenses
# ==============================================================================

def test_missing_human_approval(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 5a: Transfer above approval threshold ($5,000) proposed without approval."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 7500.0},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.REQUIRE_APPROVAL
    assert decision.rule_id == "builtin-approval-gate"
    assert decision.severity == Severity.MEDIUM
    assert "requires explicit human approval" in decision.reason
    assert "supervisor" in decision.evaluated_constraints["required_approver_roles"]


def test_approval_forgery_via_parameters_rejected(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Audit Check 1: Agent tries to forge approval by claiming approval_granted=True and approved_by in parameters."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={
            "amount": 7500.0,
            "approval_granted": True,
            "approved_by": "supervisor",  # Forged parameter claim
        },
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.REQUIRE_APPROVAL
    assert "Unverified approval claims in action parameters are untrusted" in decision.reason
    assert decision.evaluated_constraints["approval_id_provided"] is False
    assert decision.evaluated_constraints["forged_claim_detected"] is True


def test_approval_identities_verified_against_trusted_record(
    context_manager: TaskContextManager, engine: PolicyEngine, standard_task: TaskContext
) -> None:
    """Audit Check 2: Approvals are validated against an authoritative ApprovalRecord."""
    # Register trusted human approval
    approval = ApprovalRecord(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="director_carol",
        approver_role="finance_director",
    )
    context_manager.record_approval(approval, caller_role="finance_director")

    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={
            "amount": 7500.0,
            "approval_id": approval.approval_id,
        },
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.ALLOW
    assert decision.rule_id == "builtin-default-allow"


def test_invalid_human_approver_role(
    context_manager: TaskContextManager, engine: PolicyEngine, standard_task: TaskContext
) -> None:
    """Audit Check 2: Authoritative approval held by an unauthorized role (e.g. intern)."""
    approval = ApprovalRecord(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="intern_dave",
        approver_role="junior_intern",
    )
    context_manager.record_approval(approval, caller_role="admin")

    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={
            "amount": 7500.0,
            "approval_id": approval.approval_id,
        },
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.REQUIRE_APPROVAL
    assert "which is not authorized for this action" in decision.reason


def test_revoked_approval_rejected(
    context_manager: TaskContextManager, engine: PolicyEngine, standard_task: TaskContext
) -> None:
    """Audit Check 2: Revoked approval cannot be used to execute an action."""
    approval = ApprovalRecord(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="supervisor_alice",
        approver_role="supervisor",
    )
    context_manager.record_approval(approval, caller_role="admin")
    context_manager.revoke_approval(approval.approval_id, caller_role="supervisor")

    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 7500.0, "approval_id": approval.approval_id},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.REQUIRE_APPROVAL
    assert "has been revoked or invalidated" in decision.reason


def test_cross_task_approval_replay_blocked(
    context_manager: TaskContextManager, engine: PolicyEngine, standard_task: TaskContext
) -> None:
    """Audit Check 2: Approval issued for Task A cannot be replayed on Task B."""
    other_task = TaskContext(
        task_id="task-other-002",
        original_instruction="Other task",
        allowed_actions=[ActionType.TRANSFER],
        allowed_entities=["vendor:acme-corp"],
    )
    context_manager.create_task(other_task)

    # Issue approval for other_task
    approval = ApprovalRecord(
        task_id="task-other-002",
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="supervisor_alice",
        approver_role="supervisor",
    )
    context_manager.record_approval(approval, caller_role="admin")

    # Attempt to replay on standard_task
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 7500.0, "approval_id": approval.approval_id},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert "Cross-task approval replay attack blocked" in decision.reason


# ==============================================================================
# 6. Expired Task
# ==============================================================================

def test_expired_task(context_manager: TaskContextManager, engine: PolicyEngine) -> None:
    """Scenario 6: Agent proposes an action on a task whose expiration time has elapsed."""
    expired_task = TaskContext(
        task_id="task-time-expired",
        original_instruction="Old maintenance task.",
        task_status=TaskStatus.ACTIVE,
        expiration_time=datetime.now(timezone.utc) - timedelta(minutes=5),
        allowed_actions=[ActionType.READ],
        allowed_entities=["system:metrics"],
    )
    context_manager.create_task(expired_task)

    action = Action(
        task_id="task-time-expired",
        action_type=ActionType.READ,
        target_entity="system:metrics",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-task-expiration"
    assert decision.severity == Severity.HIGH
    assert "expired at" in decision.reason
    assert context_manager.get_task("task-time-expired").task_status == TaskStatus.EXPIRED


# ==============================================================================
# 7. Revoked & Completed Tasks (Lifecycle Invariants)
# ==============================================================================

def test_revoked_task(context_manager: TaskContextManager, engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Scenario 7: Agent proposes an action on a task that was revoked by an operator."""
    context_manager.revoke_task(standard_task.task_id, reason="Operator emergency stop")

    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-task-status"
    assert decision.severity == Severity.CRITICAL
    assert "is in 'revoked' status" in decision.reason


def test_completed_task_action_blocked(
    context_manager: TaskContextManager, engine: PolicyEngine, standard_task: TaskContext
) -> None:
    """Audit Check 4: Actions on completed tasks must be blocked."""
    context_manager.update_status(standard_task.task_id, TaskStatus.COMPLETED)

    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-task-status"
    assert "is in 'completed' status" in decision.reason


# ==============================================================================
# 8. Invalid & Malformed Security Contexts
# ==============================================================================

def test_invalid_task_context_nonexistent(engine: PolicyEngine) -> None:
    """Scenario 8a: Action references a task_id that does not exist."""
    action = Action(
        task_id="ghost-task-nonexistent",
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-task-missing"
    assert decision.severity == Severity.CRITICAL
    assert "No task context registered" in decision.reason


def test_invalid_task_context_empty_id(engine: PolicyEngine) -> None:
    """Scenario 8b: Action has an empty or whitespace task_id."""
    action = Action(
        task_id="   ",
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-task-missing"
    assert "empty or invalid" in decision.reason


def test_malformed_none_action(engine: PolicyEngine) -> None:
    """Audit Check 8: Passing None or invalid object to evaluate returns BLOCK safely."""
    decision = engine.evaluate(None)  # type: ignore[arg-type]
    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-malformed-action"


# ==============================================================================
# Monetary Value Validation (Audit Check 6)
# ==============================================================================

@pytest.mark.parametrize(
    "invalid_amount, expected_reason",
    [
        (-100.0, "Negative amounts"),
        (-0.01, "Negative amounts"),
        (float("nan"), "cannot be NaN"),
        (float("inf"), "cannot be infinite"),
        (float("-inf"), "cannot be infinite"),
        ("not_a_number", "cannot be converted"),
    ],
)
def test_monetary_value_validation(
    engine: PolicyEngine, standard_task: TaskContext, invalid_amount, expected_reason: str
) -> None:
    """Audit Check 6: Validate negative, NaN, infinite, and malformed amounts are blocked."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": invalid_amount},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-transaction-limit"
    assert expected_reason in decision.reason


# ==============================================================================
# Malformed Action Parameters (Audit Check 7)
# ==============================================================================

def test_malformed_target_entity_empty_whitespace(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Audit Check 7: Actions with empty or whitespace target entities are blocked."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.READ,
        target_entity="   ",
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-invalid-target-entity"
    assert "missing, empty, or whitespace" in decision.reason


# ==============================================================================
# Self-Modification & Policy Configuration
# ==============================================================================

def test_agent_self_modification_blocked(engine: PolicyEngine, standard_task: TaskContext) -> None:
    """Audit Check 3: Agent targets task_context or permissions; must be strictly BLOCKED."""
    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.MODIFY,
        target_entity="task_context",
        parameters={"allowed_actions": ["delete", "transfer", "execute"]},
        requested_by="agent",
    )

    decision = engine.evaluate(action)

    assert decision.verdict == Verdict.BLOCK
    assert decision.rule_id == "builtin-prevent-self-modification"
    assert decision.severity == Severity.CRITICAL
    assert "strictly forbidden from modifying task permissions" in decision.reason


def test_configurable_policy_engine(context_manager: TaskContextManager, standard_task: TaskContext) -> None:
    """Verify that PolicyEngine can accept a custom Policy object."""
    custom_policy = Policy(
        name="custom_audit_policy",
        rules=[
            PolicyRule(
                rule_id="audit-rule-01",
                rule_type=PolicyRuleType.ACTION_PERMISSION,
                description="Custom policy check",
                enabled=True,
            )
        ],
    )
    custom_engine = PolicyEngine(context_manager=context_manager, policy=custom_policy)

    action = Action(
        task_id=standard_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )
    decision = custom_engine.evaluate(action)
    assert decision.verdict == Verdict.ALLOW
