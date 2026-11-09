"""Tests for adversarial scenario execution and regression replay runner in AGENTGUARD simulator."""

from __future__ import annotations

import pytest

from backend.security.models import (
    Action,
    ActionType,
    TaskContext,
    Verdict,
)
from backend.simulator.runner import SandboxRunner
from backend.simulator.scenarios import (
    build_forged_approval_scenario,
    build_legitimate_approved_workflow_scenario,
    build_limit_breach_scenario,
    build_sanctioned_payment_scenario,
    build_self_modification_scenario,
    get_standard_scenarios,
)


@pytest.fixture
def runner() -> SandboxRunner:
    return SandboxRunner()


def test_all_standard_scenarios_pass_verdict_verification(
    runner: SandboxRunner,
) -> None:
    """Every standardized scenario in the catalog executes and matches expected verdicts."""
    scenarios = get_standard_scenarios()
    assert len(scenarios) >= 5

    for scenario in scenarios:
        result = runner.run_scenario(scenario)
        assert result.passed is True, (
            f"Scenario '{scenario.name}' ({scenario.scenario_id}) failed: {result.verdict_mismatches}"
        )
        assert len(result.action_results) == len(scenario.actions)
        assert len(result.verdict_mismatches) == 0


def test_individual_sanctioned_payment_scenario(runner: SandboxRunner) -> None:
    scenario = build_sanctioned_payment_scenario()
    result = runner.run_scenario(scenario)
    assert result.passed is True
    assert result.action_results[0].decision.decision == Verdict.ALLOW
    assert result.action_results[1].decision.decision == Verdict.BLOCK


def test_individual_limit_breach_scenario(runner: SandboxRunner) -> None:
    scenario = build_limit_breach_scenario()
    result = runner.run_scenario(scenario)
    assert result.passed is True
    assert result.action_results[1].decision.decision == Verdict.BLOCK


def test_individual_forged_approval_scenario(runner: SandboxRunner) -> None:
    scenario = build_forged_approval_scenario()
    result = runner.run_scenario(scenario)
    assert result.passed is True
    assert result.action_results[1].decision.decision == Verdict.REQUIRE_APPROVAL


def test_individual_self_modification_scenario(runner: SandboxRunner) -> None:
    scenario = build_self_modification_scenario()
    result = runner.run_scenario(scenario)
    assert result.passed is True
    assert result.action_results[0].decision.decision == Verdict.BLOCK


def test_individual_approved_workflow_scenario(runner: SandboxRunner) -> None:
    scenario = build_legitimate_approved_workflow_scenario()
    result = runner.run_scenario(scenario)
    assert result.passed is True
    assert result.action_results[0].decision.decision == Verdict.ALLOW
    assert result.action_results[1].decision.decision == Verdict.ALLOW


def test_custom_action_trace_replay(runner: SandboxRunner) -> None:
    """SandboxRunner can replay an arbitrary trace of actions against a task context."""
    task = TaskContext(
        task_id="trace-test-task",
        original_instruction="Replay action trace",
        allowed_actions=[ActionType.READ],
        allowed_entities=["invoice:acme-101"],
    )
    trace = [
        Action(
            task_id=task.task_id,
            action_type=ActionType.READ,
            target_entity="invoice:acme-101",
        ),
        Action(
            task_id=task.task_id,
            action_type=ActionType.DELETE,  # Unauthorized
            target_entity="invoice:acme-101",
        ),
    ]

    results = runner.run_trace(trace, task)
    assert len(results) == 2
    assert results[0].decision.decision == Verdict.ALLOW
    assert results[1].decision.decision == Verdict.BLOCK


# ==============================================================================
# Remediation Regression Tests (SEC-04-001 & SEC-04-002)
# ==============================================================================

def test_simulation_sandbox_reset_repopulates_fixtures() -> None:
    """SEC-04-002: SimulationSandbox.reset(reseed=True) re-seeds standard fixtures."""
    from backend.simulator.sandbox import SimulationSandbox

    sandbox = SimulationSandbox()
    assert len(sandbox.state.list_accounts()) > 0
    assert len(sandbox.state.list_vendors()) > 0

    # Modify state: debit balance
    sandbox.state.update_balance("acc-operating-001", 1000.0)
    assert sandbox.state.get_account("acc-operating-001").balance == 1000.0

    # Reset with reseed=True (default)
    sandbox.reset()
    assert sandbox.state.get_account("acc-operating-001").balance == 50000.0
    assert len(sandbox.state.list_vendors()) > 0

    # Reset with reseed=False clears completely
    sandbox.reset(reseed=False)
    assert len(sandbox.state.list_accounts()) == 0
    assert len(sandbox.state.list_vendors()) == 0


def test_runner_end_to_end_mode_dispatches_real_tools_and_updates_state(
    runner: SandboxRunner,
) -> None:
    """SEC-04-001: End-to-end execution dispatches real guarded tools and asserts state."""
    scenario = build_legitimate_approved_workflow_scenario()
    result = runner.run_scenario(scenario, mode="end_to_end")

    assert result.passed is True
    assert result.verdict_passed is True
    assert result.execution_passed is True
    assert len(result.verdict_mismatches) == 0
    assert len(result.execution_mismatches) == 0

    # Verify both actions executed successfully
    assert result.action_results[0].executed is True
    assert result.action_results[0].success is True
    assert result.action_results[1].executed is True
    assert result.action_results[1].success is True

    # Verify state was genuinely updated: $50,000 - $7,500 = $42,500
    acc = runner.sandbox.state.get_account("acc-operating-001")
    assert acc is not None
    assert acc.balance == 42500.0
    assert len(runner.sandbox.state.list_payments()) == 1


def test_runner_policy_only_mode_does_not_modify_state(
    runner: SandboxRunner,
) -> None:
    """SEC-04-001: Policy-only mode uses dummy execution without altering state."""
    scenario = build_legitimate_approved_workflow_scenario()
    result = runner.run_scenario(scenario, mode="policy_only")

    assert result.passed is True
    assert result.verdict_passed is True
    # State remains unmutated at initial $50,000 balance
    acc = runner.sandbox.state.get_account("acc-operating-001")
    assert acc is not None
    assert acc.balance == 50000.0
    assert len(runner.sandbox.state.list_payments()) == 0


def test_runner_detects_state_assertion_failure(runner: SandboxRunner) -> None:
    """SEC-04-001: Runner flags failure when post-scenario state assertion fails."""
    scenario = build_legitimate_approved_workflow_scenario()
    # Override state assertion to require an impossible balance
    scenario.state_assertions = lambda state: state.get_account("acc-operating-001").balance == 999999.0

    result = runner.run_scenario(scenario, mode="end_to_end")
    assert result.verdict_passed is True
    assert result.execution_passed is False
    assert result.passed is False
    assert any("Post-scenario state assertions failed" in m for m in result.execution_mismatches)


def test_blocked_actions_never_execute_tool_in_runner(
    runner: SandboxRunner,
) -> None:
    """SEC-04-001: Invariant check — blocked actions never execute underlying tools."""
    scenario = build_sanctioned_payment_scenario()
    result = runner.run_scenario(scenario, mode="end_to_end")

    assert result.passed is True
    # Action 0 (read) was ALLOWed and executed
    assert result.action_results[0].decision.decision == Verdict.ALLOW
    assert result.action_results[0].executed is True

    # Action 1 (sanctioned transfer) was BLOCKED and must NOT have executed
    assert result.action_results[1].decision.decision == Verdict.BLOCK
    assert result.action_results[1].executed is False
    assert len(runner.sandbox.state.list_payments()) == 0
