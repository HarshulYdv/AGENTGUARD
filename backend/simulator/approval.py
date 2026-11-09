"""Human-in-the-loop approval workflow service for AGENTGUARD simulation.

Simulates supervisory actions (granting or revoking approvals out-of-band)
using the authoritative TaskContextManager approval registry.
"""

from __future__ import annotations

from typing import Optional

from backend.security.context import AUTHORIZED_APPROVER_ROLES, TaskContextManager
from backend.security.models import ActionType, ApprovalRecord


class ApprovalService:
    """Out-of-band approval service simulating human supervisor actions."""

    def __init__(self, context_manager: TaskContextManager) -> None:
        self._ctx_mgr = context_manager

    def grant_approval(
        self,
        task_id: str,
        action_type: ActionType,
        target_entity: str,
        approved_by: str,
        approver_role: str,
        max_amount: Optional[float] = None,
    ) -> ApprovalRecord:
        """Issue an authoritative ApprovalRecord on behalf of an authorized supervisor."""
        if approver_role not in AUTHORIZED_APPROVER_ROLES:
            raise PermissionError(
                f"Role '{approver_role}' is not in authorized approver roles: {sorted(AUTHORIZED_APPROVER_ROLES)}"
            )

        record = ApprovalRecord(
            task_id=task_id,
            action_type=action_type,
            target_entity=target_entity,
            approved_by=approved_by,
            approver_role=approver_role,
            max_approved_amount=max_amount,
        )
        return self._ctx_mgr.record_approval(record, caller_role=approver_role)

    def revoke_approval(self, approval_id: str, caller_role: str) -> ApprovalRecord:
        """Revoke an existing approval record."""
        return self._ctx_mgr.revoke_approval(approval_id, caller_role=caller_role)

    def get_approval(self, approval_id: str) -> Optional[ApprovalRecord]:
        """Lookup an approval record by ID."""
        return self._ctx_mgr.get_approval(approval_id)

