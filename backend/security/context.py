"""TaskContextManager — lifecycle management for agent security contexts.

Responsible for creating, retrieving, updating, revoking, and validating
task contexts. Every mutation strictly revalidates the resulting model via
TaskContext.model_validate(). An agent can never modify its own permissions;
all mutations require the caller to hold an administrative role.
Approval records are maintained in an authoritative, write-protected store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.core.logging import get_logger
from backend.security.models import (
    ActionType,
    ApprovalRecord,
    ApprovalRequirement,
    TaskContext,
    TaskStatus,
)

logger = get_logger("security.context")

# Whitelist of roles permitted to record or manage authoritative approvals
AUTHORIZED_APPROVER_ROLES = {
    "supervisor",
    "finance_director",
    "security_supervisor",
    "admin",
    "system",
}


class TaskContextManager:
    """In-memory registry of active task contexts and authoritative approvals.

    Each task context is stored by ``task_id`` and carries its own
    immutable permission boundaries. The manager enforces lifecycle
    transitions, full model revalidation on every mutation, constraint
    maintenance, expiration checks, and write-protected approval records.
    """

    def __init__(self) -> None:
        self._contexts: Dict[str, TaskContext] = {}
        self._approvals: Dict[str, ApprovalRecord] = {}

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_task(self, context: TaskContext) -> TaskContext:
        """Register a new task context.

        Strictly validates the model via model_validate().
        Raises ``ValueError`` if a task with the same ID already exists.
        """
        if context.task_id in self._contexts:
            raise ValueError(
                f"Task context with id '{context.task_id}' already exists."
            )
        # Revalidate model payload to ensure complete structural validity
        validated = TaskContext.model_validate(context.model_dump())
        self._contexts[validated.task_id] = validated
        logger.info(
            f"Created task context '{validated.task_id}' "
            f"with {len(validated.allowed_actions)} allowed actions."
        )
        return validated.model_copy(deep=True)

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_task(self, task_id: str) -> Optional[TaskContext]:
        """Return a defensive, immutable copy of the task context for *task_id*, or ``None``."""
        context = self._contexts.get(task_id)
        if context is not None:
            # Check expiration and update if necessary
            context = self._check_and_expire(context)
            return context.model_copy(deep=True)
        return None

    # ------------------------------------------------------------------
    # Update status
    # ------------------------------------------------------------------

    def update_status(self, task_id: str, new_status: TaskStatus) -> TaskContext:
        """Transition a task to *new_status*.

        Strictly revalidates via TaskContext.model_validate().
        Raises ``KeyError`` if the task does not exist and ``ValueError``
        for illegal transitions (e.g. resurrection of completed, revoked, or expired tasks).
        """
        context = self._contexts.get(task_id)
        if context is None:
            raise KeyError(f"Task context '{task_id}' not found.")

        # Prevent resurrection of terminal states
        terminal = {TaskStatus.REVOKED, TaskStatus.EXPIRED, TaskStatus.COMPLETED}
        if context.task_status in terminal:
            raise ValueError(
                f"Cannot transition task '{task_id}' from terminal "
                f"state '{context.task_status.value}'."
            )

        updated_dict = context.model_dump()
        updated_dict["task_status"] = new_status
        validated_context = TaskContext.model_validate(updated_dict)
        self._contexts[task_id] = validated_context

        logger.info(f"Task '{task_id}' transitioned to '{new_status.value}'.")
        return validated_context.model_copy(deep=True)

    # ------------------------------------------------------------------
    # Revoke
    # ------------------------------------------------------------------

    def revoke_task(self, task_id: str, reason: str = "") -> TaskContext:
        """Irrevocably revoke a task context.

        Strictly revalidates via TaskContext.model_validate().
        Once revoked the task cannot be reactivated.
        """
        context = self._contexts.get(task_id)
        if context is None:
            raise KeyError(f"Task context '{task_id}' not found.")

        updated_dict = context.model_dump()
        updated_dict["task_status"] = TaskStatus.REVOKED
        updated_dict["metadata"]["revocation_reason"] = reason
        validated_context = TaskContext.model_validate(updated_dict)
        self._contexts[task_id] = validated_context

        logger.warning(
            f"Task '{task_id}' REVOKED. Reason: {reason or 'none provided'}."
        )
        return validated_context.model_copy(deep=True)

    # ------------------------------------------------------------------
    # Validate Task Expiration
    # ------------------------------------------------------------------

    def validate_expiration(self, task_id: str) -> bool:
        """Check whether task *task_id* has expired.

        Returns ``True`` if the task has expired, ``False`` if still valid.
        Raises ``KeyError`` if the task does not exist.
        """
        context = self._contexts.get(task_id)
        if context is None:
            raise KeyError(f"Task context '{task_id}' not found.")

        updated = self._check_and_expire(context)
        return updated.task_status == TaskStatus.EXPIRED

    def is_expired(self, task_id: str) -> bool:
        """Convenience alias for validate_expiration."""
        return self.validate_expiration(task_id)

    # ------------------------------------------------------------------
    # Maintain Task Constraints
    # ------------------------------------------------------------------

    def update_constraints(
        self,
        task_id: str,
        caller_role: str,
        *,
        allowed_actions: Optional[List[ActionType]] = None,
        denied_actions: Optional[List[ActionType]] = None,
        allowed_entities: Optional[List[str]] = None,
        restricted_entities: Optional[List[str]] = None,
        transaction_limits: Optional[Dict[str, float]] = None,
        approval_requirements: Optional[List[ApprovalRequirement]] = None,
    ) -> TaskContext:
        """Update security constraints on an existing task.

        Strictly revalidates via TaskContext.model_validate().
        SECURITY INVARIANT:
        Agents are strictly forbidden from modifying task constraints.
        Only 'admin', 'security_supervisor', or 'system' roles may adjust constraints.
        """
        authorized_roles = {"admin", "security_supervisor", "system"}
        if caller_role.lower() not in authorized_roles:
            logger.error(
                f"Security violation: Unauthorized role '{caller_role}' "
                f"attempted to modify constraints on task '{task_id}'."
            )
            raise PermissionError(
                f"Role '{caller_role}' is not authorized to modify task constraints. "
                "Agents cannot modify their own security boundaries."
            )

        context = self._contexts.get(task_id)
        if context is None:
            raise KeyError(f"Task context '{task_id}' not found.")

        if context.task_status != TaskStatus.ACTIVE:
            raise ValueError(
                f"Cannot update constraints for task in '{context.task_status.value}' state."
            )

        updated_dict = context.model_dump()
        if allowed_actions is not None:
            updated_dict["allowed_actions"] = [a.value if isinstance(a, ActionType) else a for a in allowed_actions]
        if denied_actions is not None:
            updated_dict["denied_actions"] = [a.value if isinstance(a, ActionType) else a for a in denied_actions]
        if allowed_entities is not None:
            updated_dict["allowed_entities"] = list(allowed_entities)
        if restricted_entities is not None:
            updated_dict["restricted_entities"] = list(restricted_entities)
        if transaction_limits is not None:
            updated_dict["transaction_limits"] = dict(transaction_limits)
        if approval_requirements is not None:
            updated_dict["approval_requirements"] = [
                req.model_dump() if isinstance(req, ApprovalRequirement) else req
                for req in approval_requirements
            ]

        validated_context = TaskContext.model_validate(updated_dict)
        self._contexts[task_id] = validated_context
        logger.info(f"Task constraints updated for '{task_id}' by '{caller_role}'.")
        return validated_context.model_copy(deep=True)

    # ------------------------------------------------------------------
    # Authoritative Approval Store (Write-Protected)
    # ------------------------------------------------------------------

    def record_approval(
        self, approval: ApprovalRecord, caller_role: str = "supervisor"
    ) -> ApprovalRecord:
        """Register a trusted human approval.

        SECURITY INVARIANTS:
        1. Only explicitly whitelisted human roles can record approvals.
        2. Caller role must match the approver role (or hold admin/system role).
        3. Model is strictly revalidated via ApprovalRecord.model_validate().
        """
        caller_role_norm = caller_role.lower().strip()
        if caller_role_norm not in AUTHORIZED_APPROVER_ROLES:
            logger.error(
                f"Security violation: Unauthorized role '{caller_role}' "
                f"attempted to record approval '{approval.approval_id}'."
            )
            raise PermissionError(
                f"Role '{caller_role}' is not authorized to record human approvals. "
                f"Allowed roles: {sorted(AUTHORIZED_APPROVER_ROLES)}."
            )

        if caller_role_norm not in {"admin", "system"}:
            if caller_role_norm != approval.approver_role.lower().strip():
                raise PermissionError(
                    f"Caller role '{caller_role}' cannot record approval on behalf of "
                    f"role '{approval.approver_role}'."
                )

        validated_approval = ApprovalRecord.model_validate(approval.model_dump())
        self._approvals[validated_approval.approval_id] = validated_approval

        logger.info(
            f"Recorded trusted approval '{validated_approval.approval_id}' by '{validated_approval.approved_by}' "
            f"({validated_approval.approver_role}) for task '{validated_approval.task_id}'."
        )
        return validated_approval.model_copy(deep=True)

    def get_approval(self, approval_id: str) -> Optional[ApprovalRecord]:
        """Retrieve a registered approval record, or None."""
        approval = self._approvals.get(approval_id)
        if approval is not None:
            return approval.model_copy(deep=True)
        return None

    def revoke_approval(
        self, approval_id: str, caller_role: str = "supervisor"
    ) -> ApprovalRecord:
        """Revoke a previously recorded approval."""
        caller_role_norm = caller_role.lower().strip()
        if caller_role_norm not in AUTHORIZED_APPROVER_ROLES:
            raise PermissionError(f"Role '{caller_role}' is not authorized to revoke approvals.")

        approval = self._approvals.get(approval_id)
        if approval is None:
            raise KeyError(f"Approval record '{approval_id}' not found.")

        updated_dict = approval.model_dump()
        updated_dict["valid"] = False
        revoked = ApprovalRecord.model_validate(updated_dict)
        self._approvals[approval_id] = revoked

        logger.warning(f"Revoked approval '{approval_id}' by '{caller_role}'.")
        return revoked.model_copy(deep=True)

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def is_valid(self, task_id: str) -> bool:
        """Return ``True`` only when the task exists and is ``ACTIVE``."""
        context = self.get_task(task_id)
        if context is None:
            return False
        return context.task_status == TaskStatus.ACTIVE

    def _check_and_expire(self, context: TaskContext) -> TaskContext:
        """Mark a context as EXPIRED in the store if its deadline has passed."""
        if (
            context.task_status == TaskStatus.ACTIVE
            and context.expiration_time is not None
            and datetime.now(timezone.utc) >= context.expiration_time
        ):
            updated_dict = context.model_dump()
            updated_dict["task_status"] = TaskStatus.EXPIRED
            validated_context = TaskContext.model_validate(updated_dict)
            self._contexts[context.task_id] = validated_context

            logger.info(
                f"Task '{context.task_id}' auto-expired at "
                f"{context.expiration_time.isoformat()}."
            )
            return validated_context
        return context

    # ------------------------------------------------------------------
    # Bulk helpers (useful for dashboard / evaluation)
    # ------------------------------------------------------------------

    def list_tasks(self, *, status: Optional[TaskStatus] = None) -> list[TaskContext]:
        """Return defensive copies of all contexts, optionally filtered by status."""
        for task_id in list(self._contexts.keys()):
            self._check_and_expire(self._contexts[task_id])
        if status is None:
            return [c.model_copy(deep=True) for c in self._contexts.values()]
        return [
            c.model_copy(deep=True)
            for c in self._contexts.values()
            if c.task_status == status
        ]

    def clear(self) -> None:
        """Remove every registered context and approval (test utility)."""
        self._contexts.clear()
        self._approvals.clear()
