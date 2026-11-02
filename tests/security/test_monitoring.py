"""Unit and integration tests for Runtime Monitoring Engine, Gateway, and Interceptor (Stage 03).

Covers all required security controls and acceptance criteria:
  1. Test all three decisions (ALLOW, BLOCK, REQUIRE_APPROVAL).
  2. Acceptance Criterion: Unauthorized payment NEVER reaches the execution function.
  3. Execution bypass attempts (direct bypass rejected).
  4. Duplicate execution prevention (single-use authorization).
  5. Invalid, forged, and replayed approvals (single-use approval token).
  6. Action ordering and workflow trajectory anomaly detection.
  7. Fail-closed behavior on monitoring failures.
  8. Structured security event generation.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest

from backend.security.context import TaskContextManager
from backend.security.engine import PolicyEngine
from backend.security.events import SecurityEventEmitter, SecurityEventType
from backend.security.gateway import (
    ApprovalReplayError,
    DuplicateExecutionError,
    ExecutionBlockedError,
    ExecutionGateway,
    ExecutionResult,
)
from backend.security.interceptor import ActionInterceptor
from backend.security.models import (
    Action,
    ActionType,
    ApprovalRecord,
    ApprovalRequirement,
    Severity,
    TaskContext,
    TaskStatus,
    Verdict,
)
from backend.security.monitoring import MonitoringDecision, MonitoringEngine
from backend.security.tracker import AnomalyType, TrajectoryTracker


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def context_manager() -> TaskContextManager:
    return TaskContextManager()


@pytest.fixture
def policy_engine(context_manager: TaskContextManager) -> PolicyEngine:
    return PolicyEngine(context_manager=context_manager)


@pytest.fixture
def event_emitter() -> SecurityEventEmitter:
    return SecurityEventEmitter()


@pytest.fixture
def tracker() -> TrajectoryTracker:
    return TrajectoryTracker(max_repeated_sensitive=3)


@pytest.fixture
def monitoring_engine(
    context_manager: TaskContextManager,
    policy_engine: PolicyEngine,
    tracker: TrajectoryTracker,
    event_emitter: SecurityEventEmitter,
) -> MonitoringEngine:
    return MonitoringEngine(
        context_manager=context_manager,
        policy_engine=policy_engine,
        tracker=tracker,
        event_emitter=event_emitter,
    )


@pytest.fixture
def gateway(monitoring_engine: MonitoringEngine) -> ExecutionGateway:
    return ExecutionGateway(monitoring_engine=monitoring_engine)


@pytest.fixture
def interceptor(gateway: ExecutionGateway) -> ActionInterceptor:
    return ActionInterceptor(gateway=gateway)


@pytest.fixture
def payment_task(context_manager: TaskContextManager) -> TaskContext:
    """Setup a standard payment processing task with limit of $10,000 and approval at $5,000."""
    task = TaskContext(
        task_id="task-finance-payment-001",
        original_instruction="Inspect invoices and disburse payments to ACME Corp up to $10,000.",
        allowed_actions=[ActionType.READ, ActionType.TRANSFER],
        denied_actions=[ActionType.DELETE],
        allowed_entities=["invoice:acme-101", "vendor:acme-corp"],
        restricted_entities=["vendor:sanctioned-offshore"],
        transaction_limits={"transfer": 10000.0},
        approval_requirements=[
            ApprovalRequirement(
                action_types=[ActionType.TRANSFER],
                min_amount=5000.0,
                approver_roles=["finance_director", "supervisor"],
            )
        ],
    )
    return context_manager.create_task(task)


# ==============================================================================
# 1. Test All Three Decisions (ALLOW, BLOCK, REQUIRE_APPROVAL)
# ==============================================================================

def test_decision_allow_executes_tool(
    interceptor: ActionInterceptor, payment_task: TaskContext
) -> None:
    """ALLOW decision authorizes execution and returns tool output."""
    mock_tool = MagicMock(return_value={"status": "read_ok", "content": "invoice data"})

    action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
        parameters={"format": "json"},
    )

    result = interceptor.intercept(action, mock_tool, "arg1", kwarg1="val1")

    assert result.executed is True
    assert result.decision.decision == Verdict.ALLOW
    assert result.result == {"status": "read_ok", "content": "invoice data"}
    assert result.error is None
    mock_tool.assert_called_once_with("arg1", kwarg1="val1")


def test_decision_block_never_invokes_tool(
    interceptor: ActionInterceptor, payment_task: TaskContext
) -> None:
    """BLOCK decision halts execution immediately; tool is NEVER called."""
    mock_tool = MagicMock()

    action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.DELETE,  # Explicitly denied
        target_entity="invoice:acme-101",
    )

    result = interceptor.intercept(action, mock_tool)

    assert result.executed is False
    assert result.decision.decision == Verdict.BLOCK
    assert result.result is None
    assert "Execution blocked by security policy" in result.error
    mock_tool.assert_not_called()


def test_decision_require_approval_pauses_execution(
    interceptor: ActionInterceptor, payment_task: TaskContext
) -> None:
    """REQUIRE_APPROVAL decision pauses execution; tool is NEVER called."""
    # First, simulate a prerequisite read to satisfy action ordering
    read_action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )
    interceptor.intercept(read_action, lambda: None)

    mock_tool = MagicMock()

    # Transfer $7,500 without approval
    transfer_action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 7500.0},
    )

    result = interceptor.intercept(transfer_action, mock_tool)

    assert result.executed is False
    assert result.decision.decision == Verdict.REQUIRE_APPROVAL
    assert "Execution paused" in result.error
    mock_tool.assert_not_called()


# ==============================================================================
# 2. Acceptance Criterion: Unauthorized Payment NEVER Reaches Tool
# ==============================================================================

def test_unauthorized_payment_never_reaches_execution_function(
    interceptor: ActionInterceptor, payment_task: TaskContext
) -> None:
    """ACCEPTANCE: Demonstrate that an unauthorized payment never reaches the execution function."""
    mock_banking_transfer_tool = MagicMock(return_value={"tx_id": "disbursed-9999"})

    # Attack Vector 1: Beneficiary is a sanctioned entity
    sanctioned_attack = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:sanctioned-offshore",
        parameters={"amount": 1000.0},
    )
    res1 = interceptor.intercept(sanctioned_attack, mock_banking_transfer_tool)
    assert res1.executed is False
    mock_banking_transfer_tool.assert_not_called()

    # Attack Vector 2: Amount exceeds transaction limit ($25,000 > $10,000)
    overlimit_attack = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 25000.0},
    )
    res2 = interceptor.intercept(overlimit_attack, mock_banking_transfer_tool)
    assert res2.executed is False
    mock_banking_transfer_tool.assert_not_called()

    # Attack Vector 3: Negative amount underflow attempt
    negative_attack = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": -5000.0},
    )
    res3 = interceptor.intercept(negative_attack, mock_banking_transfer_tool)
    assert res3.executed is False
    mock_banking_transfer_tool.assert_not_called()

    # Tool invocation count must be exactly ZERO across all unauthorized attempts
    assert mock_banking_transfer_tool.call_count == 0


# ==============================================================================
# 3. Execution Bypass Attempts & Tool Wrapping
# ==============================================================================

def test_tool_wrapping_enforces_interception(
    interceptor: ActionInterceptor, payment_task: TaskContext
) -> None:
    """Verify ActionInterceptor.wrap_tool transparently enforces security checks."""
    raw_tool = MagicMock(return_value="executed_ok")

    def action_builder(inv_id: str, fmt: str) -> Action:
        return Action(
            task_id=payment_task.task_id,
            action_type=ActionType.READ,
            target_entity=inv_id,
            parameters={"format": fmt},
        )

    secured_tool = interceptor.wrap_tool(raw_tool, action_builder)

    # Valid call
    result = secured_tool("invoice:acme-101", "pdf")
    assert result.executed is True
    assert result.result == "executed_ok"
    raw_tool.assert_called_once_with("invoice:acme-101", "pdf")

    # Unauthorized entity call
    blocked_result = secured_tool("invoice:unauthorized-999", "pdf")
    assert blocked_result.executed is False
    assert raw_tool.call_count == 1  # Not called again


# ==============================================================================
# 4. Duplicate Execution Guard (Single-Use Authorization)
# ==============================================================================

def test_duplicate_execution_attempt_blocked(
    gateway: ExecutionGateway, payment_task: TaskContext
) -> None:
    """An action cannot be executed twice through the same authorization."""
    mock_tool = MagicMock(return_value="done")
    action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )

    # First execution -> succeeds
    res1 = gateway.execute(action, mock_tool)
    assert res1.executed is True
    mock_tool.assert_called_once()

    # Second execution of the exact same action_id -> rejected
    res2 = gateway.execute(action, mock_tool)
    assert res2.executed is False
    assert "Duplicate execution is prohibited" in res2.error
    assert mock_tool.call_count == 1  # Tool was not called second time

    # If raise_on_blocked is requested, raises DuplicateExecutionError
    with pytest.raises(DuplicateExecutionError):
        gateway.execute(action, mock_tool, raise_on_blocked=True)


# ==============================================================================
# 5. Approval Replay Guard & Single-Use Token Consumption
# ==============================================================================

def test_approval_replay_blocked(
    context_manager: TaskContextManager,
    interceptor: ActionInterceptor,
    payment_task: TaskContext,
) -> None:
    """An approval token cannot be replayed for multiple separate actions."""
    # Prerequisite read
    interceptor.intercept(
        Action(task_id=payment_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: None,
    )

    # Register trusted human approval
    approval = ApprovalRecord(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="director_carol",
        approver_role="finance_director",
        max_approved_amount=7500.0,
    )
    context_manager.record_approval(approval, caller_role="finance_director")

    mock_transfer = MagicMock(return_value="tx_123")

    # Action 1: Valid execution with approval
    action1 = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 7000.0, "approval_id": approval.approval_id},
    )
    res1 = interceptor.intercept(action1, mock_transfer)
    assert res1.executed is True
    mock_transfer.assert_called_once()

    # Action 2: Replay of the exact same approval_id on a new action
    action2 = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 7000.0, "approval_id": approval.approval_id},
    )
    res2 = interceptor.intercept(action2, mock_transfer)
    assert res2.executed is False
    assert "already been consumed" in res2.error
    assert mock_transfer.call_count == 1  # Replay did not reach tool


def test_approval_amount_ceiling_enforcement(
    context_manager: TaskContextManager,
    interceptor: ActionInterceptor,
    payment_task: TaskContext,
) -> None:
    """An approval bound to $5,000 cannot authorize an escalated $6,000 transfer."""
    interceptor.intercept(
        Action(task_id=payment_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: None,
    )

    approval = ApprovalRecord(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="supervisor_alice",
        approver_role="supervisor",
        max_approved_amount=5000.0,  # Explicit ceiling
    )
    context_manager.record_approval(approval, caller_role="supervisor")

    mock_tool = MagicMock()
    # Attempt $6,000 using the $5,000 approval
    action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 6000.0, "approval_id": approval.approval_id},
    )

    res = interceptor.intercept(action, mock_tool)
    assert res.executed is False
    assert "exceeds the maximum amount" in res.error
    mock_tool.assert_not_called()


# ==============================================================================
# 6. Action Ordering & Trajectory Anomalies
# ==============================================================================

def test_suspicious_action_ordering_blocked(
    interceptor: ActionInterceptor, payment_task: TaskContext
) -> None:
    """Attempting an irreversible transfer as the first action with no prior read is blocked."""
    mock_tool = MagicMock()

    # Propose high-impact transfer without any prior read
    action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 1000.0},
    )

    result = interceptor.intercept(action, mock_tool)

    assert result.executed is False
    assert result.decision.decision == Verdict.BLOCK
    assert "Workflow anomaly detected" in result.error
    assert "Action 'transfer' proposed without prior inspection" in result.error
    mock_tool.assert_not_called()


def test_repeated_sensitive_operations_anomaly(
    context_manager: TaskContextManager,
    monitoring_engine: MonitoringEngine,
    payment_task: TaskContext,
) -> None:
    """Burst of 3+ consecutive transfer attempts flags REPEATED_SENSITIVE_OPERATIONS."""
    tracker = monitoring_engine.tracker

    # First read
    r1 = Action(task_id=payment_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101")
    monitoring_engine.inspect(r1)

    # 3 consecutive transfer attempts
    for i in range(3):
        act = Action(
            task_id=payment_task.task_id,
            action_type=ActionType.TRANSFER,
            target_entity="vendor:acme-corp",
            parameters={"amount": 1000.0},
        )
        monitoring_engine.inspect(act)

    # 4th transfer attempt should detect the anomaly
    act_4 = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 1000.0},
    )
    anomalies = tracker.analyze_trajectory(payment_task.task_id, act_4)
    anomaly_types = [a.anomaly_type for a in anomalies]
    assert AnomalyType.REPEATED_SENSITIVE_OPERATIONS in anomaly_types


# ==============================================================================
# 7. Fail Closed on Monitoring Failure
# ==============================================================================

def test_fail_closed_on_monitoring_exception(
    context_manager: TaskContextManager,
    payment_task: TaskContext,
) -> None:
    """When the monitoring engine encounters an unexpected crash, it fails closed (BLOCK)."""
    # Create an engine with a broken policy engine that raises RuntimeError
    bad_policy_engine = MagicMock()
    bad_policy_engine.evaluate.side_effect = RuntimeError("Database connection pool exhausted")

    engine = MonitoringEngine(
        context_manager=context_manager,
        policy_engine=bad_policy_engine,
    )
    gateway = ExecutionGateway(monitoring_engine=engine)
    mock_tool = MagicMock()

    action = Action(
        task_id=payment_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )

    res = gateway.execute(action, mock_tool)

    assert res.executed is False
    assert res.decision.decision == Verdict.BLOCK
    assert res.decision.severity == Severity.CRITICAL
    assert "failed closed" in res.decision.explanation
    mock_tool.assert_not_called()


# ==============================================================================
# 8. Security Event Auditing
# ==============================================================================

def test_security_event_generation(
    interceptor: ActionInterceptor,
    monitoring_engine: MonitoringEngine,
    payment_task: TaskContext,
) -> None:
    """Verify structured events are recorded for all key security outcomes."""
    events = monitoring_engine.event_emitter

    # Allowed read
    interceptor.intercept(
        Action(task_id=payment_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: "ok",
    )
    # Blocked action
    interceptor.intercept(
        Action(task_id=payment_task.task_id, action_type=ActionType.DELETE, target_entity="invoice:acme-101"),
        lambda: "ok",
    )

    all_events = events.get_events(task_id=payment_task.task_id)
    event_types = [e.event_type for e in all_events]

    assert SecurityEventType.ACTION_ALLOWED in event_types
    assert SecurityEventType.EXECUTION_SUCCESS in event_types
    assert SecurityEventType.ACTION_BLOCKED in event_types

