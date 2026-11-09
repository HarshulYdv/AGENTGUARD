"""Tests for deterministic fault injection in AGENTGUARD simulator."""

from __future__ import annotations

import pytest

from backend.security.events import SecurityEventType
from backend.security.models import ActionType, TaskContext, Verdict
from backend.simulator.faults import (
    FaultConfig,
    FaultType,
    SimulatedTimeoutError,
)
from backend.simulator.sandbox import SimulationSandbox


@pytest.fixture
def sandbox() -> SimulationSandbox:
    return SimulationSandbox()


@pytest.fixture
def fault_task(sandbox: SimulationSandbox) -> TaskContext:
    task = TaskContext(
        task_id="task-sim-faults-01",
        original_instruction="Read vendor invoices with simulated network faults.",
        allowed_actions=[ActionType.READ],
        allowed_entities=["invoice:acme-101"],
    )
    return sandbox.context_manager.create_task(task)


def test_deterministic_timeout_fault_injection(
    sandbox: SimulationSandbox, fault_task: TaskContext
) -> None:
    """Simulated timeout fires after ALLOW, accurately recorded as executed=True, success=False."""
    # Register deterministic network timeout on read_invoice
    sandbox.fault_injector.register_fault(
        FaultConfig(
            fault_type=FaultType.NETWORK_TIMEOUT,
            affected_tools=["read_invoice"],
            error_message="Simulated ERP timeout (read timeout 5000ms)",
        )
    )

    res = sandbox.read_invoice(fault_task.task_id, "invoice:acme-101")

    # Invariants:
    # 1. Action was authorized (ALLOW)
    assert res.decision.decision == Verdict.ALLOW
    # 2. Tool was invoked (executed = True)
    assert res.executed is True
    # 3. Tool failed (success = False)
    assert res.success is False
    assert "Simulated ERP timeout" in res.error

    # 4. Trajectory recorded failure accurately
    hist = sandbox.tracker.get_executed_actions(fault_task.task_id)
    assert len(hist) == 1
    assert "Simulated ERP timeout" in hist[0].error

    # 5. Security event emitted
    fail_events = sandbox.events.get_events(
        event_type=SecurityEventType.EXECUTION_FAILURE
    )
    assert len(fail_events) == 1
    assert "Simulated ERP timeout" in fail_events[0].details["error"]


def test_fault_max_triggers_and_recovery(
    sandbox: SimulationSandbox, fault_task: TaskContext
) -> None:
    """Fault fires for max_triggers count, then subsequent invocations succeed."""
    sandbox.fault_injector.register_fault(
        FaultConfig(
            fault_type=FaultType.SERVER_ERROR,
            affected_tools=["read_invoice"],
            max_triggers=1,
            error_message="HTTP 503 Service Unavailable",
        )
    )

    # First attempt: fails due to fault
    res1 = sandbox.read_invoice(fault_task.task_id, "invoice:acme-101")
    assert res1.executed is True
    assert res1.success is False

    # Second attempt: fault exhausted, invocation succeeds
    res2 = sandbox.read_invoice(fault_task.task_id, "invoice:acme-101")
    assert res2.executed is True
    assert res2.success is True
    assert res2.result["amount"] == 2500.0


# ==============================================================================
# Remediation Regression Tests (SEC-04-007)
# ==============================================================================

def test_multiple_fault_configs_do_not_collide_trigger_counts() -> None:
    """SEC-04-007: Multiple fault configs with same fault_type must have independent counters."""
    from backend.simulator.faults import FaultInjector

    injector = FaultInjector()
    rule1 = FaultConfig(
        fault_type=FaultType.NETWORK_TIMEOUT,
        affected_tools=["test_tool"],
        max_triggers=1,
    )
    rule2 = FaultConfig(
        fault_type=FaultType.NETWORK_TIMEOUT,
        affected_tools=["test_tool"],
        max_triggers=1,
    )

    injector.register_fault(rule1)
    injector.register_fault(rule2)

    # First call: triggers rule1
    f1 = injector.should_fault("test_tool")
    assert f1 is not None
    assert f1.rule_id == rule1.rule_id

    # Second call: rule1 is exhausted (max_triggers=1). Must trigger rule2, not skip it!
    f2 = injector.should_fault("test_tool")
    assert f2 is not None
    assert f2.rule_id == rule2.rule_id

    # Third call: both rule1 and rule2 are exhausted
    f3 = injector.should_fault("test_tool")
    assert f3 is None


def test_fault_injector_reset_reproducibility() -> None:
    """SEC-04-007: reset() must re-seed the internal PRNG for reproducible test runs."""
    from backend.simulator.faults import FaultInjector

    injector = FaultInjector(seed=999)
    prob_rule = FaultConfig(
        fault_type=FaultType.RATE_LIMIT,
        probability=0.5,
        affected_tools=["api_tool"],
    )
    injector.register_fault(prob_rule)

    # Collect 10 sequence outcomes
    seq1 = [injector.should_fault("api_tool") is not None for _ in range(10)]

    # Reset injector
    injector.reset()
    prob_rule_re = FaultConfig(
        rule_id=prob_rule.rule_id,
        fault_type=FaultType.RATE_LIMIT,
        probability=0.5,
        affected_tools=["api_tool"],
    )
    injector.register_fault(prob_rule_re)

    # Collect 10 sequence outcomes after reset
    seq2 = [injector.should_fault("api_tool") is not None for _ in range(10)]

    # Must be 100% identical sequence
    assert seq1 == seq2

