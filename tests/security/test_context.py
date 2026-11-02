"""Unit tests for TaskContextManager."""

import pytest
from datetime import datetime, timedelta, timezone
from pydantic import ValidationError

from backend.security.context import TaskContextManager
from backend.security.models import (
    ActionType,
    ApprovalRecord,
    ApprovalRequirement,
    TaskContext,
    TaskStatus,
)


@pytest.fixture
def manager() -> TaskContextManager:
    """Fresh TaskContextManager for each test."""
    return TaskContextManager()


@pytest.fixture
def sample_context() -> TaskContext:
    """Standard task context for invoice processing."""
    return TaskContext(
        task_id="task-invoice-001",
        original_instruction="Process invoices for ACME Corp.",
        allowed_actions=[ActionType.READ, ActionType.WRITE],
        allowed_entities=["invoice:acme-001", "invoice:acme-002"],
        restricted_entities=["invoice:secret-999"],
        transaction_limits={"transfer": 10000.0},
    )


class TestTaskCreation:
    def test_create_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        result = manager.create_task(sample_context)
        assert result.task_id == "task-invoice-001"
        assert result.task_status == TaskStatus.ACTIVE

    def test_create_duplicate_raises(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        with pytest.raises(ValueError, match="already exists"):
            manager.create_task(sample_context)


class TestTaskRetrieval:
    def test_get_existing_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        retrieved = manager.get_task("task-invoice-001")
        assert retrieved is not None
        assert retrieved.task_id == "task-invoice-001"

    def test_get_missing_task_returns_none(self, manager: TaskContextManager) -> None:
        assert manager.get_task("nonexistent") is None


class TestTaskStatusUpdates:
    def test_update_to_completed(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        result = manager.update_status("task-invoice-001", TaskStatus.COMPLETED)
        assert result.task_status == TaskStatus.COMPLETED

    def test_update_missing_task_raises(self, manager: TaskContextManager) -> None:
        with pytest.raises(KeyError, match="not found"):
            manager.update_status("nonexistent", TaskStatus.COMPLETED)

    def test_cannot_revive_revoked_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        manager.revoke_task("task-invoice-001", reason="Security breach")
        with pytest.raises(ValueError, match="terminal state"):
            manager.update_status("task-invoice-001", TaskStatus.ACTIVE)

    def test_cannot_revive_completed_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        """Security Audit Check 4: Completed tasks must never be resurrected."""
        manager.create_task(sample_context)
        manager.update_status("task-invoice-001", TaskStatus.COMPLETED)
        with pytest.raises(ValueError, match="terminal state 'completed'"):
            manager.update_status("task-invoice-001", TaskStatus.ACTIVE)

    def test_cannot_revive_expired_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        """Security Audit Check 4: Expired tasks must never be resurrected."""
        manager.create_task(sample_context)
        manager.update_status("task-invoice-001", TaskStatus.EXPIRED)
        with pytest.raises(ValueError, match="terminal state 'expired'"):
            manager.update_status("task-invoice-001", TaskStatus.ACTIVE)


class TestTaskRevocation:
    def test_revoke_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        result = manager.revoke_task("task-invoice-001", reason="Compromised agent")
        assert result.task_status == TaskStatus.REVOKED
        assert result.metadata["revocation_reason"] == "Compromised agent"

    def test_revoke_missing_task_raises(self, manager: TaskContextManager) -> None:
        with pytest.raises(KeyError, match="not found"):
            manager.revoke_task("nonexistent")


class TestTaskExpiration:
    def test_auto_expire_past_deadline(self, manager: TaskContextManager) -> None:
        expired_context = TaskContext(
            task_id="task-expired",
            original_instruction="Expired task",
            expiration_time=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        manager.create_task(expired_context)

        retrieved = manager.get_task("task-expired")
        assert retrieved is not None
        assert retrieved.task_status == TaskStatus.EXPIRED

    def test_active_before_deadline(self, manager: TaskContextManager) -> None:
        future_context = TaskContext(
            task_id="task-future",
            original_instruction="Still valid",
            expiration_time=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        manager.create_task(future_context)

        retrieved = manager.get_task("task-future")
        assert retrieved is not None
        assert retrieved.task_status == TaskStatus.ACTIVE

    def test_validate_expiration_method(self, manager: TaskContextManager) -> None:
        expired_context = TaskContext(
            task_id="task-val-expired",
            original_instruction="Expired check",
            expiration_time=datetime.now(timezone.utc) - timedelta(minutes=10),
        )
        active_context = TaskContext(
            task_id="task-val-active",
            original_instruction="Active check",
            expiration_time=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        manager.create_task(expired_context)
        manager.create_task(active_context)

        assert manager.validate_expiration("task-val-expired") is True
        assert manager.validate_expiration("task-val-active") is False

    def test_validate_expiration_missing_task_raises(self, manager: TaskContextManager) -> None:
        with pytest.raises(KeyError, match="not found"):
            manager.validate_expiration("unknown-task")


class TestTaskImmutability:
    """Security Audit Check 3 & 5: Ensure task contexts are genuinely immutable to callers."""

    def test_direct_attribute_mutation_prevented(self, sample_context: TaskContext) -> None:
        with pytest.raises(ValidationError):
            sample_context.allowed_actions = [ActionType.DELETE]

    def test_retrieved_context_mutation_does_not_affect_store(
        self, manager: TaskContextManager, sample_context: TaskContext
    ) -> None:
        manager.create_task(sample_context)
        retrieved = manager.get_task("task-invoice-001")
        assert retrieved is not None

        # Mutating a local list reference on retrieved copy must not affect stored copy
        retrieved.allowed_actions.append(ActionType.DELETE)
        fresh = manager.get_task("task-invoice-001")
        assert fresh is not None
        assert ActionType.DELETE not in fresh.allowed_actions


class TestMaintainConstraints:
    def test_admin_can_update_constraints(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        updated = manager.update_constraints(
            "task-invoice-001",
            caller_role="admin",
            allowed_actions=[ActionType.READ],
            transaction_limits={"transfer": 5000.0},
        )
        assert updated.allowed_actions == [ActionType.READ]
        assert updated.transaction_limits == {"transfer": 5000.0}

    def test_agent_cannot_modify_own_constraints(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        with pytest.raises(PermissionError, match="not authorized to modify task constraints"):
            manager.update_constraints(
                "task-invoice-001",
                caller_role="agent",
                allowed_actions=[ActionType.DELETE, ActionType.TRANSFER],
            )


class TestApprovalStore:
    """Security Audit Check 1 & 2: Authoritative approval registry."""

    def test_supervisor_can_record_approval(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        approval = ApprovalRecord(
            task_id=sample_context.task_id,
            action_type=ActionType.TRANSFER,
            approved_by="supervisor_bob",
            approver_role="supervisor",
        )
        recorded = manager.record_approval(approval, caller_role="supervisor")
        assert recorded.approval_id == approval.approval_id
        assert manager.get_approval(approval.approval_id) is not None

    def test_agent_cannot_record_approval(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        approval = ApprovalRecord(
            task_id=sample_context.task_id,
            action_type=ActionType.TRANSFER,
            approved_by="agent",
            approver_role="agent",
        )
        with pytest.raises(PermissionError, match="not authorized to record human approvals"):
            manager.record_approval(approval, caller_role="agent")

    def test_revoke_approval(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        approval = ApprovalRecord(
            task_id=sample_context.task_id,
            action_type=ActionType.TRANSFER,
            approved_by="director_carol",
            approver_role="finance_director",
        )
        manager.record_approval(approval, caller_role="finance_director")
        revoked = manager.revoke_approval(approval.approval_id, caller_role="finance_director")
        assert revoked.valid is False
        assert manager.get_approval(approval.approval_id).valid is False


class TestTaskValidation:
    def test_is_valid_active_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        assert manager.is_valid("task-invoice-001") is True

    def test_is_valid_nonexistent_task(self, manager: TaskContextManager) -> None:
        assert manager.is_valid("nonexistent") is False

    def test_is_valid_revoked_task(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        manager.revoke_task("task-invoice-001")
        assert manager.is_valid("task-invoice-001") is False


class TestBulkOperations:
    def test_list_all_tasks(self, manager: TaskContextManager) -> None:
        for i in range(3):
            manager.create_task(
                TaskContext(task_id=f"task-{i}", original_instruction=f"Task {i}")
            )
        assert len(manager.list_tasks()) == 3

    def test_list_by_status(self, manager: TaskContextManager) -> None:
        manager.create_task(
            TaskContext(task_id="task-a", original_instruction="Active task")
        )
        manager.create_task(
            TaskContext(task_id="task-b", original_instruction="To be completed")
        )
        manager.update_status("task-b", TaskStatus.COMPLETED)

        active = manager.list_tasks(status=TaskStatus.ACTIVE)
        assert len(active) == 1
        assert active[0].task_id == "task-a"

    def test_clear(self, manager: TaskContextManager, sample_context: TaskContext) -> None:
        manager.create_task(sample_context)
        manager.clear()
        assert len(manager.list_tasks()) == 0
