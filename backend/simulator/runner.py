"""SandboxRunner — Regression replay and scenario evaluation harness for AGENTGUARD.

Executes adversarial and compliance scenarios against isolated simulation sandboxes,
verifying deterministic verdict alignment and collecting security audit trails.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.security.events import SecurityEvent
from backend.security.gateway import ExecutionResult
from backend.security.models import Action, TaskContext, Verdict
from backend.simulator.sandbox import SimulationSandbox
from backend.simulator.scenarios import AdversarialScenario


class ScenarioResult(BaseModel):
    """Forensic report resulting from executing an AdversarialScenario."""

    scenario_id: str = Field(
        description="ID of the evaluated scenario.",
    )
    name: str = Field(
        description="Scenario title.",
    )
    passed: bool = Field(
        description="Whether all action verdicts and execution outcomes matched expected criteria.",
    )
    verdict_passed: bool = Field(
        default=True,
        description="Whether all action verdicts matched expected outcomes exactly.",
    )
    execution_passed: bool = Field(
        default=True,
        description="Whether tool executions and state assertions passed.",
    )
    total_actions: int = Field(
        description="Total actions evaluated in sequence.",
    )
    verdict_mismatches: List[str] = Field(
        default_factory=list,
        description="Detailed mismatch descriptions if any step differed from expected.",
    )
    execution_mismatches: List[str] = Field(
        default_factory=list,
        description="Detailed execution or state mismatch descriptions.",
    )
    action_results: List[ExecutionResult] = Field(
        default_factory=list,
        description="Chronological list of execution gateway results.",
    )
    events: List[SecurityEvent] = Field(
        default_factory=list,
        description="Audit events emitted during scenario run.",
    )


class SandboxRunner:
    """Orchestrates scenario execution and trace replay against clean simulation states."""

    def __init__(self, sandbox: Optional[SimulationSandbox] = None) -> None:
        self._sandbox = sandbox or SimulationSandbox()

    @property
    def sandbox(self) -> SimulationSandbox:
        return self._sandbox

    def run_scenario(
        self, scenario: AdversarialScenario, mode: str = "end_to_end"
    ) -> ScenarioResult:
        """Run an adversarial scenario from a clean state and evaluate verdicts and execution.

        Args:
            scenario: The AdversarialScenario definition.
            mode: "end_to_end" (default) invokes actual guarded simulator tools and verifies
                  execution outcomes and state assertions. "policy_only" evaluates monitoring
                  verdicts using abstract dummy tools without side effects.
        """
        # 1. Reset sandbox to clean state with default seed data
        self._sandbox.reset(reseed=True)

        # 2. Register task context
        self._sandbox.context_manager.create_task(scenario.task_context)

        # 3. Pre-register any approvals
        for app in scenario.approvals:
            self._sandbox.context_manager.record_approval(
                app, caller_role=app.approver_role
            )

        def _dummy_tool(*args: Any, **kwargs: Any) -> Dict[str, str]:
            return {"status": "executed_in_simulation"}

        action_results: List[ExecutionResult] = []
        verdict_mismatches: List[str] = []
        execution_mismatches: List[str] = []

        # 4. Evaluate actions in sequence
        for idx, (action, expected) in enumerate(
            zip(scenario.actions, scenario.expected_verdicts)
        ):
            if mode == "end_to_end":
                tool_fn, args, kwargs = self._sandbox.resolve_tool_for_action(action)
                res = self._sandbox.gateway.execute(action, tool_fn, *args, **kwargs)
            else:
                res = self._sandbox.gateway.execute(action, _dummy_tool)

            action_results.append(res)
            actual_verdict = res.decision.decision

            # Verify authorization decision
            if actual_verdict != expected:
                verdict_mismatches.append(
                    f"Step {idx + 1} ({action.action_type.value} -> '{action.target_entity}'): "
                    f"Expected verdict {expected.value}, got {actual_verdict.value}. "
                    f"Explanation: {res.decision.explanation}"
                )

            # In end-to-end mode, verify tool execution outcome integrity
            if mode == "end_to_end":
                if actual_verdict == Verdict.ALLOW:
                    if not res.executed:
                        execution_mismatches.append(
                            f"Step {idx + 1}: Action '{action.action_id}' was ALLOWed but tool was not executed."
                        )
                    elif not res.success:
                        execution_mismatches.append(
                            f"Step {idx + 1}: Tool execution failed for ALLOWed action '{action.action_id}': {res.error}"
                        )
                else:
                    if res.executed:
                        execution_mismatches.append(
                            f"Step {idx + 1}: Security invariant violated! Tool was executed for non-ALLOW verdict {actual_verdict.value}."
                        )

        # 5. Verify post-scenario state assertions in end-to-end mode
        if mode == "end_to_end" and scenario.state_assertions is not None:
            try:
                assert_result = scenario.state_assertions(self._sandbox.state)
                if not assert_result:
                    execution_mismatches.append(
                        f"Post-scenario state assertions failed for scenario '{scenario.scenario_id}'."
                    )
            except Exception as exc:
                execution_mismatches.append(
                    f"Post-scenario state assertions raised exception: {exc}"
                )

        verdict_passed = len(verdict_mismatches) == 0
        execution_passed = len(execution_mismatches) == 0
        passed = verdict_passed and execution_passed
        events = self._sandbox.events.get_events(task_id=scenario.task_context.task_id)

        return ScenarioResult(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            passed=passed,
            verdict_passed=verdict_passed,
            execution_passed=execution_passed,
            total_actions=len(scenario.actions),
            verdict_mismatches=verdict_mismatches,
            execution_mismatches=execution_mismatches,
            action_results=action_results,
            events=events,
        )

    def run_trace(
        self,
        actions: List[Action],
        task_context: TaskContext,
        tool_callable: Optional[Callable[..., Any]] = None,
    ) -> List[ExecutionResult]:
        """Replay an arbitrary list of actions under a task context."""
        self._sandbox.context_manager.create_task(task_context)
        callable_fn = tool_callable or (lambda *a, **kw: {"status": "replayed"})
        results: List[ExecutionResult] = []
        for action in actions:
            res = self._sandbox.gateway.execute(action, callable_fn)
            results.append(res)
        return results

