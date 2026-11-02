"""Pydantic v2 domain models for AGENTGUARD task-aware security.

All security decisions are based on deterministic evaluation of these
structured models — never on LLM-generated claims or implicit defaults.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TaskStatus(str, Enum):
    """Lifecycle states for an agent task."""

    ACTIVE = "active"
    COMPLETED = "completed"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


class ActionType(str, Enum):
    """Categorised operation types an agent may attempt."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    TRANSFER = "transfer"
    APPROVE = "approve"
    MODIFY = "modify"


class Verdict(str, Enum):
    """Outcome of a policy evaluation."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Severity(str, Enum):
    """Risk severity attached to a policy decision."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyRuleType(str, Enum):
    """Discriminator for different policy rule categories."""

    ACTION_PERMISSION = "action_permission"
    ENTITY_RESTRICTION = "entity_restriction"
    TRANSACTION_LIMIT = "transaction_limit"
    TASK_SCOPE = "task_scope"
    APPROVAL_GATE = "approval_gate"
    TASK_EXPIRATION = "task_expiration"
    TASK_STATUS = "task_status"
    SELF_MODIFICATION = "self_modification"


# ---------------------------------------------------------------------------
# Approval requirement
# ---------------------------------------------------------------------------

class ApprovalRequirement(BaseModel):
    """Describes a human-in-the-loop approval gate for specific action types."""

    action_types: List[ActionType] = Field(
        description="Action types that require explicit human approval.",
    )
    min_amount: Optional[float] = Field(
        default=None,
        description="Minimum monetary amount that triggers the approval gate.",
    )
    approver_roles: List[str] = Field(
        default_factory=lambda: ["supervisor", "finance_director"],
        description="Roles authorised to grant approval.",
    )


class ApprovalRecord(BaseModel):
    """Authoritative, tamper-proof record of human approval granted out-of-band."""

    model_config = ConfigDict(frozen=True)

    approval_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique approval identifier.",
    )
    task_id: str = Field(
        description="Task context ID this approval is bound to.",
    )
    action_type: ActionType = Field(
        description="Specific action type approved.",
    )
    target_entity: Optional[str] = Field(
        default=None,
        description="Approved target entity (or None for any authorized entity in task).",
    )
    approved_by: str = Field(
        description="Verified identity of the human approver.",
    )
    approver_role: str = Field(
        description="Verified role of the human approver.",
    )
    max_approved_amount: Optional[float] = Field(
        default=None,
        description="Maximum monetary amount authorized under this approval.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the approval was granted.",
    )
    valid: bool = Field(
        default=True,
        description="Whether this approval is active and not revoked.",
    )


# ---------------------------------------------------------------------------
# Task Context
# ---------------------------------------------------------------------------

class TaskContext(BaseModel):
    """Immutable security boundary for an autonomous agent task.

    Every field has a safe default — missing data results in the most
    restrictive interpretation (deny-by-default).
    """

    model_config = ConfigDict(frozen=True)

    task_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique task identifier.",
    )
    original_instruction: str = Field(
        description="The verbatim instruction assigned to the agent.",
    )
    task_status: TaskStatus = Field(
        default=TaskStatus.ACTIVE,
        description="Current lifecycle status of the task.",
    )
    creation_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the task was created.",
    )
    expiration_time: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp after which the task is considered expired.",
    )

    # Permission boundaries
    allowed_actions: List[ActionType] = Field(
        default_factory=list,
        description="Exhaustive whitelist of permitted action types.",
    )
    denied_actions: List[ActionType] = Field(
        default_factory=list,
        description="Explicit blacklist taking precedence over allowed_actions.",
    )
    allowed_entities: List[str] = Field(
        default_factory=list,
        description="Entity identifiers the agent is allowed to interact with.",
    )
    restricted_entities: List[str] = Field(
        default_factory=list,
        description="Entity identifiers the agent must never interact with.",
    )

    # Financial controls
    transaction_limits: Dict[str, float] = Field(
        default_factory=dict,
        description=(
            "Per-action-type monetary ceiling. "
            "Keys are ActionType values; values are maximum amounts."
        ),
    )

    # Approval gates
    approval_requirements: List[ApprovalRequirement] = Field(
        default_factory=list,
        description="Human-in-the-loop gates that must be satisfied.",
    )

    # Extensible metadata
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary context metadata (e.g. department, project).",
    )


# ---------------------------------------------------------------------------
# Action (proposed operation)
# ---------------------------------------------------------------------------

class Action(BaseModel):
    """Describes a single operation the agent wants to perform."""

    action_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this action request.",
    )
    task_id: str = Field(
        description="The task context under which this action is proposed.",
    )
    action_type: ActionType = Field(
        description="Category of the operation.",
    )
    target_entity: str = Field(
        description="Identifier of the resource or entity being acted upon.",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Operation-specific parameters (e.g. amount, payload).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the action was proposed.",
    )
    previous_action_id: Optional[str] = Field(
        default=None,
        description="Chaining reference to the preceding action, if any.",
    )
    requested_by: str = Field(
        default="agent",
        description="Identity of the requester (always treated as untrusted).",
    )


# ---------------------------------------------------------------------------
# Policy Rule
# ---------------------------------------------------------------------------

class PolicyRule(BaseModel):
    """A single deterministic rule evaluated by the PolicyEngine."""

    rule_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique rule identifier.",
    )
    rule_type: PolicyRuleType = Field(
        description="Category of the policy check.",
    )
    description: str = Field(
        default="",
        description="Human-readable explanation of what this rule enforces.",
    )
    severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Risk level if this rule triggers a block.",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Rule-specific parameters or threshold configurations.",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this rule is active.",
    )


# ---------------------------------------------------------------------------
# Policy Model
# ---------------------------------------------------------------------------

class Policy(BaseModel):
    """Configurable security policy aggregating rules for action permissions,
    entity restrictions, transaction limits, approval gates, and task scopes."""

    policy_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique policy identifier.",
    )
    name: str = Field(
        default="default_policy",
        description="Human-readable policy name.",
    )
    description: str = Field(
        default="",
        description="Explanation of what this policy enforces.",
    )
    rules: List[PolicyRule] = Field(
        default_factory=list,
        description="Ordered list of configurable policy rules.",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this policy configuration is active.",
    )


# ---------------------------------------------------------------------------
# Policy Decision
# ---------------------------------------------------------------------------

class PolicyDecision(BaseModel):
    """Structured, auditable result of evaluating an action against policies."""

    decision_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique decision identifier for audit trails.",
    )
    action_id: str = Field(
        description="The action that was evaluated.",
    )
    task_id: str = Field(
        description="The task context used during evaluation.",
    )
    verdict: Verdict = Field(
        description="Final authorization outcome: ALLOW, BLOCK, or REQUIRE_APPROVAL.",
    )
    rule_id: str = Field(
        description="The rule that determined the verdict.",
    )
    reason: str = Field(
        description="Human-readable explanation of the decision.",
    )
    severity: Severity = Field(
        description="Risk severity associated with the decision.",
    )
    evaluated_constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of the constraints that were checked.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the decision was rendered.",
    )
