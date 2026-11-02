"""Adversarial Security Audit Test Suite for AGENTGUARD Stage 03.

Performs rigorous adversarial verification of:
  1. Concurrent duplicate action submission prevention (atomic lock + in-flight guard).
  2. Concurrent approval consumption race prevention (atomic single-use token guard).
  3. Strict binding of approval records to task, action type, beneficiary, and amount.
  4. Interception bypass prevention for wrapped tools and forged parameters.
  5. Fail-closed execution prevention under internal monitoring exceptions.
  6. Accurate recording of underlying tool failures without false success states.
  7. Strict separation of proposed actions and executed actions in trajectory tracker.
  8. Prevention of policy bypass via action retries and detection of repetition loops.
  9. In-memory lifetime guarantees and documented cold restart boundary.
  10. Comprehensive security event emission across all security outcomes.
"""

from __future__ import annotations

import concurrent.futures
import time
from datetime import datetime, timezone
from typing import Any, List
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
def secure_finance_task(context_manager: TaskContextManager) -> TaskContext:
    """Setup a hardened payment task with limits, entity restrictions, and approval requirements."""
    task = TaskContext(
        task_id="task-adv-finance-001",
        original_instruction="Disburse vendor invoices up to $10,000 for approved entities.",
        allowed_actions=[ActionType.READ, ActionType.TRANSFER],
        denied_actions=[ActionType.DELETE],
        allowed_entities=["invoice:acme-101", "vendor:acme-corp"],
        restricted_entities=["vendor:rogue-entity", "vendor:sanctioned-offshore"],
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
# 1. Concurrent Duplicate Action Submission (Check 1)
# ==============================================================================

def test_concurrent_duplicate_action_submissions(
    gateway: ExecutionGateway,
    interceptor: ActionInterceptor,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 1: 10 concurrent threads submit the exact same action.
    
    Verifies that despite concurrency, the tool is executed EXACTLY ONCE,
    and all 9 other threads are atomically blocked with DUPLICATE_EXECUTION_ATTEMPT.
    """
    # Satisfy prerequisite read to ensure workflow ordering passes
    read_action = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )
    gateway.execute(read_action, lambda: "read_ok")

    execution_counter = 0

    def slow_tool() -> str:
        nonlocal execution_counter
        execution_counter += 1
        time.sleep(0.03)  # Widen the race window
        return "payment_sent"

    # Action within standard limit ($1,000 < $5,000 -> ALLOW)
    action = Action(
        action_id="concurrent-action-unique-001",
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 1000.0},
    )

    num_threads = 10
    results: List[ExecutionResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(gateway.execute, action, slow_tool) for _ in range(num_threads)]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    # Invariant: Tool must be called EXACTLY ONCE
    assert execution_counter == 1

    # Invariant: Exactly 1 result executed, 9 blocked
    executed_results = [r for r in results if r.executed]
    blocked_results = [r for r in results if not r.executed]

    assert len(executed_results) == 1
    assert executed_results[0].success is True
    assert executed_results[0].result == "payment_sent"

    assert len(blocked_results) == num_threads - 1
    for r in blocked_results:
        assert r.success is False
        assert "Duplicate execution is prohibited" in r.error

    # Invariant: Security events emitted for duplicate execution attempts
    dup_events = gateway.monitoring_engine.event_emitter.get_events(
        event_type=SecurityEventType.DUPLICATE_EXECUTION_ATTEMPT
    )
    assert len(dup_events) == num_threads - 1


# ==============================================================================
# 2. Concurrent Approval Token Consumption Race (Check 2)
# ==============================================================================

def test_concurrent_approval_token_consumption_race(
    context_manager: TaskContextManager,
    gateway: ExecutionGateway,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 2: 10 concurrent threads submit 10 DIFFERENT actions sharing 1 approval.
    
    Verifies that the approval token is consumed atomically: EXACTLY ONE action executes,
    and 9 concurrent actions are blocked with APPROVAL_REPLAY_ATTEMPT.
    """
    # Prerequisite read
    gateway.execute(
        Action(
            task_id=secure_finance_task.task_id,
            action_type=ActionType.READ,
            target_entity="invoice:acme-101",
        ),
        lambda: "read_ok",
    )

    # Register single-use approval for $8,000 transfer
    approval = ApprovalRecord(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="director_carol",
        approver_role="finance_director",
        max_approved_amount=8000.0,
    )
    context_manager.record_approval(approval, caller_role="finance_director")

    execution_counter = 0

    def slow_transfer_tool(action_id: str) -> str:
        nonlocal execution_counter
        execution_counter += 1
        time.sleep(0.03)  # Widen race window
        return f"disbursed_for_{action_id}"

    num_threads = 10
    # 10 distinct actions sharing the same approval_id
    actions = [
        Action(
            action_id=f"raced-action-{i}",
            task_id=secure_finance_task.task_id,
            action_type=ActionType.TRANSFER,
            target_entity="vendor:acme-corp",
            parameters={"amount": 7500.0, "approval_id": approval.approval_id},
        )
        for i in range(num_threads)
    ]

    results: List[ExecutionResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(gateway.execute, act, slow_transfer_tool, act.action_id)
            for act in actions
        ]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    # Invariant: Approval can only authorize EXACTLY ONE execution
    assert execution_counter == 1

    executed_results = [r for r in results if r.executed]
    blocked_results = [r for r in results if not r.executed]

    assert len(executed_results) == 1
    assert executed_results[0].success is True
    assert "disbursed_for_raced-action-" in executed_results[0].result

    assert len(blocked_results) == num_threads - 1
    for r in blocked_results:
        assert r.success is False
        assert "already been consumed" in r.error

    # Invariant: 9 approval replay events emitted
    replay_events = gateway.monitoring_engine.event_emitter.get_events(
        event_type=SecurityEventType.APPROVAL_REPLAY_ATTEMPT
    )
    assert len(replay_events) == num_threads - 1


# ==============================================================================
# 3. Approval Record Binding to Beneficiary and Amount (Check 3)
# ==============================================================================

def test_approval_binding_to_beneficiary_preventing_redirection(
    context_manager: TaskContextManager,
    interceptor: ActionInterceptor,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 3a: Approval issued for ACME Corp cannot be redirected to another entity."""
    interceptor.intercept(
        Action(task_id=secure_finance_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: "read_ok",
    )

    approval = ApprovalRecord(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",  # Strictly bound to ACME
        approved_by="supervisor_alice",
        approver_role="supervisor",
        max_approved_amount=6000.0,
    )
    context_manager.record_approval(approval, caller_role="supervisor")

    mock_tool = MagicMock()

    # Attacker attempts to use ACME's approval token for a different entity
    attack_action = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="invoice:acme-101",  # Different entity than approved vendor:acme-corp
        parameters={"amount": 5500.0, "approval_id": approval.approval_id},
    )

    res = interceptor.intercept(attack_action, mock_tool)
    assert res.executed is False
    assert res.decision.decision == Verdict.BLOCK
    assert "was issued for entity 'vendor:acme-corp', not requested entity" in res.error
    mock_tool.assert_not_called()


def test_approval_omitted_amount_blocked(
    context_manager: TaskContextManager,
    interceptor: ActionInterceptor,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 3b: Omitting the amount parameter cannot bypass bounded approval ceiling."""
    interceptor.intercept(
        Action(task_id=secure_finance_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: "read_ok",
    )

    approval = ApprovalRecord(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="supervisor_alice",
        approver_role="supervisor",
        max_approved_amount=5000.0,  # Bound to $5,000
    )
    context_manager.record_approval(approval, caller_role="supervisor")

    mock_tool = MagicMock()

    # Attacker omits 'amount' in parameters trying to bypass max_approved_amount check
    evasion_action = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"approval_id": approval.approval_id},  # No 'amount'!
    )

    res = interceptor.intercept(evasion_action, mock_tool)
    assert res.executed is False
    assert res.decision.decision == Verdict.BLOCK
    mock_tool.assert_not_called()


# ==============================================================================
# 4. Missing Amount on Action with Transaction Limit Blocked (Check 4)
# ==============================================================================

def test_missing_amount_on_limited_action_blocked(
    interceptor: ActionInterceptor,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 4: Action with configured transaction limit must specify an amount."""
    interceptor.intercept(
        Action(task_id=secure_finance_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: "read_ok",
    )

    mock_tool = MagicMock()

    # Task has transaction_limits={"transfer": 10000.0}, agent omits amount
    action = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={},  # No amount provided
    )

    res = interceptor.intercept(action, mock_tool)
    assert res.executed is False
    assert res.decision.decision == Verdict.BLOCK
    assert "has a transaction limit of 10000.0, but no 'amount' parameter was provided" in res.error
    mock_tool.assert_not_called()


# ==============================================================================
# 5. Tool Wrapping & Parameter Spoofing Resistance (Check 5)
# ==============================================================================

def test_wrapped_tool_rejects_agent_forged_approval_parameters(
    interceptor: ActionInterceptor,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 5: Forged approval claims in parameters cannot bypass wrapped tools."""
    mock_raw_tool = MagicMock(return_value="executed_disbursement")

    def builder(target: str, amount: float, **kwargs) -> Action:
        return Action(
            task_id=secure_finance_task.task_id,
            action_type=ActionType.TRANSFER,
            target_entity=target,
            parameters={"amount": amount, **kwargs},
        )

    secured_transfer = interceptor.wrap_tool(mock_raw_tool, builder)

    # Prerequisite read
    interceptor.intercept(
        Action(task_id=secure_finance_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: "read_ok",
    )

    # Agent calls wrapped tool trying to spoof authorization
    res = secured_transfer(
        "vendor:acme-corp",
        7500.0,
        approval_granted=True,
        approved_by="supervisor_alice",
        approver_role="supervisor",
    )

    assert res.executed is False
    assert res.decision.decision == Verdict.REQUIRE_APPROVAL
    assert "Unverified approval claims in action parameters are untrusted" in res.decision.explanation
    mock_raw_tool.assert_not_called()


# ==============================================================================
# 6. Fail-Closed Execution Prevention on Monitoring Exceptions (Check 6)
# ==============================================================================

def test_fail_closed_on_context_manager_exception(
    secure_finance_task: TaskContext,
    policy_engine: PolicyEngine,
) -> None:
    """Adversarial Check 6a: If context resolution crashes, gateway fails closed."""
    broken_ctx_mgr = MagicMock()
    broken_ctx_mgr.get_task.side_effect = RuntimeError("Database disk corruption / I/O timeout")

    engine = MonitoringEngine(context_manager=broken_ctx_mgr, policy_engine=policy_engine)
    gateway = ExecutionGateway(monitoring_engine=engine)
    mock_tool = MagicMock()

    action = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )

    res = gateway.execute(action, mock_tool)

    assert res.executed is False
    assert res.success is False
    assert res.decision.decision == Verdict.BLOCK
    assert res.decision.severity == Severity.CRITICAL
    assert "failed closed" in res.decision.explanation
    mock_tool.assert_not_called()

    # Event must be emitted
    mon_events = engine.event_emitter.get_events(event_type=SecurityEventType.MONITORING_FAILURE)
    assert len(mon_events) == 1


def test_fail_closed_on_trajectory_tracker_exception(
    context_manager: TaskContextManager,
    policy_engine: PolicyEngine,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 6b: If trajectory analysis crashes, gateway fails closed."""
    broken_tracker = MagicMock()
    broken_tracker.analyze_trajectory.side_effect = ValueError("Corrupted memory buffer in tracker")

    engine = MonitoringEngine(
        context_manager=context_manager,
        policy_engine=policy_engine,
        tracker=broken_tracker,
    )
    gateway = ExecutionGateway(monitoring_engine=engine)
    mock_tool = MagicMock()

    action = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )

    res = gateway.execute(action, mock_tool)

    assert res.executed is False
    assert res.success is False
    assert res.decision.decision == Verdict.BLOCK
    assert res.decision.severity == Severity.CRITICAL
    mock_tool.assert_not_called()


# ==============================================================================
# 7. Accurate Failure Recording Without False Success (Check 7)
# ==============================================================================

def test_underlying_tool_failure_recorded_accurately_without_false_success(
    gateway: ExecutionGateway,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 7: Tool exception records executed=True, success=False, and failure event."""
    action = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )

    def failing_tool():
        raise ConnectionResetError("Remote ERP gateway unreachable (HTTP 504)")

    res = gateway.execute(action, failing_tool)

    # Invariants: Attempt was made, but did not succeed
    assert res.executed is True
    assert res.success is False
    assert res.result is None
    assert "Tool execution failed: Remote ERP gateway unreachable (HTTP 504)" in res.error

    # Tracker accurately recorded execution failure
    trajectory = gateway.monitoring_engine.tracker.get_trajectory(secure_finance_task.task_id)
    assert len(trajectory) == 1
    assert trajectory[0].executed is True
    assert "Remote ERP gateway unreachable" in trajectory[0].error

    # Security event emitted
    fail_events = gateway.monitoring_engine.event_emitter.get_events(
        event_type=SecurityEventType.EXECUTION_FAILURE
    )
    assert len(fail_events) == 1
    assert fail_events[0].severity == Severity.HIGH
    assert "Remote ERP gateway unreachable" in fail_events[0].details["error"]


# ==============================================================================
# 8. Strict Separation of Proposed vs Executed Actions (Check 8)
# ==============================================================================

def test_strict_separation_of_proposed_and_executed_actions(
    interceptor: ActionInterceptor,
    gateway: ExecutionGateway,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 8: Proposed actions never bleed into executed actions history."""
    tracker = gateway.monitoring_engine.tracker

    # 1. Propose action that gets BLOCKED (unauthorized DELETE)
    blocked_act = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.DELETE,
        target_entity="invoice:acme-101",
    )
    interceptor.intercept(blocked_act, lambda: None)

    # 2. Propose action that PAUSES on approval ($7,500 transfer without approval)
    paused_act = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        parameters={"amount": 7500.0},
    )
    interceptor.intercept(paused_act, lambda: None)

    # 3. Propose and execute an ALLOWED action
    allowed_act = Action(
        task_id=secure_finance_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )
    interceptor.intercept(allowed_act, lambda: {"status": "ok"})

    # Invariants
    all_proposed = tracker.get_proposed_actions(secure_finance_task.task_id)
    executed_only = tracker.get_executed_actions(secure_finance_task.task_id)

    # All 3 were proposed
    assert len(all_proposed) == 3
    assert [r.action.action_id for r in all_proposed] == [
        blocked_act.action_id,
        paused_act.action_id,
        allowed_act.action_id,
    ]

    # Exactly 1 was executed
    assert len(executed_only) == 1
    assert executed_only[0].action.action_id == allowed_act.action_id
    assert executed_only[0].executed is True
    assert executed_only[0].result_summary == "{'status': 'ok'}"

    # Blocked & paused actions must have executed == False
    assert all_proposed[0].executed is False
    assert all_proposed[1].executed is False


# ==============================================================================
# 9. Retried Actions Cannot Bypass Policy & Anomaly Loop Detection (Check 9)
# ==============================================================================

def test_blocked_action_retries_fail_and_trigger_loop_detection(
    interceptor: ActionInterceptor,
    gateway: ExecutionGateway,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 9: Retrying blocked actions is rejected and detects repetition loops."""
    tracker = gateway.monitoring_engine.tracker

    # Prerequisite read
    interceptor.intercept(
        Action(task_id=secure_finance_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: "read_ok",
    )

    mock_tool = MagicMock()

    # Agent repeatedly proposes transferring to a restricted entity
    for i in range(3):
        retried_act = Action(
            action_id=f"retry-attempt-{i}",
            task_id=secure_finance_task.task_id,
            action_type=ActionType.TRANSFER,
            target_entity="vendor:rogue-entity",  # Restricted entity
            parameters={"amount": 1000.0},
        )
        res = interceptor.intercept(retried_act, mock_tool)
        assert res.executed is False
        assert res.decision.decision == Verdict.BLOCK

    mock_tool.assert_not_called()

    # On the 4th consecutive attempt, repetition loop anomaly is detected
    fourth_act = Action(
        action_id="retry-attempt-4",
        task_id=secure_finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:rogue-entity",
        parameters={"amount": 1000.0},
    )
    anomalies = tracker.analyze_trajectory(secure_finance_task.task_id, fourth_act)
    anomaly_types = [a.anomaly_type for a in anomalies]
    assert AnomalyType.ACTION_REPETITION_LOOP in anomaly_types


# ==============================================================================
# 10. In-Memory Persistence Limitation & Cold Restart Simulation (Check 10)
# ==============================================================================

def test_in_memory_persistence_limitation_and_cold_restart(
    gateway: ExecutionGateway,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 10: In-memory protection holds for process lifetime; clear() documents restart."""
    mock_tool = MagicMock(return_value="executed")

    action = Action(
        action_id="persistent-action-001",
        task_id=secure_finance_task.task_id,
        action_type=ActionType.READ,
        target_entity="invoice:acme-101",
    )

    # 1. First execution in current process -> ALLOW
    res1 = gateway.execute(action, mock_tool)
    assert res1.executed is True

    # 2. Duplicate submission within current process -> BLOCKED
    res2 = gateway.execute(action, mock_tool)
    assert res2.executed is False
    assert "Duplicate execution is prohibited" in res2.error

    # 3. Simulate process restart / in-memory cache clear
    gateway.clear()

    # Documented architectural limitation: In-memory cache is reset upon application restart
    assert not gateway.is_action_executed(action.action_id)


# ==============================================================================
# 11. Comprehensive Security Event Verification (Check 11)
# ==============================================================================

def test_comprehensive_security_event_lifecycle(
    context_manager: TaskContextManager,
    interceptor: ActionInterceptor,
    gateway: ExecutionGateway,
    secure_finance_task: TaskContext,
) -> None:
    """Adversarial Check 11: Security events are emitted with forensic metadata across all outcomes."""
    events = gateway.monitoring_engine.event_emitter
    events.clear()

    # 1. ALLOWED event
    interceptor.intercept(
        Action(task_id=secure_finance_task.task_id, action_type=ActionType.READ, target_entity="invoice:acme-101"),
        lambda: "read_ok",
    )

    # 2. BLOCKED event
    interceptor.intercept(
        Action(task_id=secure_finance_task.task_id, action_type=ActionType.DELETE, target_entity="invoice:acme-101"),
        lambda: "del_ok",
    )

    # 3. APPROVAL_REQUIRED event
    interceptor.intercept(
        Action(
            task_id=secure_finance_task.task_id,
            action_type=ActionType.TRANSFER,
            target_entity="vendor:acme-corp",
            parameters={"amount": 7500.0},
        ),
        lambda: "transfer_ok",
    )

    all_events = events.get_events(task_id=secure_finance_task.task_id)
    event_types = {e.event_type for e in all_events}

    assert SecurityEventType.ACTION_ALLOWED in event_types
    assert SecurityEventType.EXECUTION_SUCCESS in event_types
    assert SecurityEventType.ACTION_BLOCKED in event_types
    assert SecurityEventType.APPROVAL_REQUIRED in event_types

    # Verify event structure integrity
    for ev in all_events:
        assert ev.event_id is not None
        assert ev.task_id == secure_finance_task.task_id
        assert ev.timestamp is not None
        assert ev.severity in {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
        assert isinstance(ev.details, dict)

