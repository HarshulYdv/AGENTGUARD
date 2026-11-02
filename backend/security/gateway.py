"""ExecutionGateway — Controlled dispatch and execution boundary for agent actions.

Enforces execution policies:
  • Actions ONLY execute after a strict ALLOW decision.
  • A REQUIRE_APPROVAL decision pauses execution until approval is authenticated.
  • A BLOCK decision NEVER reaches the underlying tool callable.
  • Prevents replay of approval tokens (atomic single-use consumption).
  • Prevents duplicate execution of authorized actions (atomic single-use authorization).
  • Thread-safe against concurrent duplicate executions and approval consumption races.
  • Records execution outcomes accurately in the TrajectoryTracker without false success states.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Set

from pydantic import BaseModel, ConfigDict, Field

from backend.core.logging import get_logger
from backend.security.events import SecurityEventType
from backend.security.models import Action, Severity, Verdict
from backend.security.monitoring import MonitoringDecision, MonitoringEngine

logger = get_logger("security.gateway")


class SecurityExecutionError(Exception):
    """Base exception for execution gateway security violations."""
    pass


class ExecutionBlockedError(SecurityExecutionError):
    """Raised when an action is blocked by security policies."""
    pass


class ApprovalRequiredError(SecurityExecutionError):
    """Raised when an action requires human approval before proceeding."""
    pass


class DuplicateExecutionError(SecurityExecutionError):
    """Raised when an agent attempts to execute an already-executed action ID."""
    pass


class ApprovalReplayError(SecurityExecutionError):
    """Raised when an agent attempts to replay a previously consumed approval token."""
    pass


class ExecutionResult(BaseModel):
    """Detailed result of an execution attempt through the gateway."""

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(
        description="ID of the action evaluated for execution.",
    )
    executed: bool = Field(
        description="Whether the underlying tool callable was invoked.",
    )
    success: bool = Field(
        default=False,
        description="Whether the tool execution completed successfully without exception.",
    )
    decision: MonitoringDecision = Field(
        description="The monitoring decision rendered by the monitoring engine.",
    )
    result: Optional[Any] = Field(
        default=None,
        description="Return value of the tool callable if execution succeeded.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error description if the action was blocked or execution failed.",
    )
    executed_at: Optional[datetime] = Field(
        default=None,
        description="UTC time the tool call executed, or None if blocked.",
    )


class ExecutionGateway:
    """Thread-safe security gateway that intercepts and controls all tool invocations."""

    def __init__(self, monitoring_engine: MonitoringEngine) -> None:
        self._engine = monitoring_engine
        # Re-entrant lock protecting concurrent action submissions and approval consumption
        self._lock = threading.RLock()
        # Set of consumed action IDs to prevent duplicate execution
        self._executed_actions: Set[str] = set()
        # Set of action IDs currently in-flight to prevent concurrent TOCTOU races
        self._in_flight_actions: Set[str] = set()
        # Set of consumed approval IDs to prevent approval token replay
        self._consumed_approvals: Set[str] = set()
        # Set of approval IDs currently in-flight
        self._in_flight_approvals: Set[str] = set()

    @property
    def monitoring_engine(self) -> MonitoringEngine:
        """Access the underlying monitoring engine."""
        return self._engine

    def execute(
        self,
        action: Action,
        tool_callable: Callable[..., Any],
        *args: Any,
        raise_on_blocked: bool = False,
        **kwargs: Any,
    ) -> ExecutionResult:
        """Evaluate an action through the monitoring engine and execute only if ALLOW.

        Guarantees:
          • If verdict is BLOCK: tool_callable is NEVER called.
          • If verdict is REQUIRE_APPROVAL: tool_callable is NEVER called.
          • Concurrent duplicate action submissions are atomically rejected.
          • Concurrent approval consumption races are atomically prevented.
          • Any unexpected exception fails closed, preventing tool execution.
        """
        approval_id_raw = action.parameters.get("approval_id")
        approval_id = str(approval_id_raw).strip() if approval_id_raw else None

        # ── 1. Atomic Concurrency & In-Flight Reservation Guard ───────
        with self._lock:
            # Check duplicate execution (already completed or currently in-flight)
            if action.action_id in self._executed_actions or action.action_id in self._in_flight_actions:
                logger.error(
                    f"Duplicate execution blocked: Action '{action.action_id}' is already executed or in-flight."
                )
                self._engine.event_emitter.emit(
                    event_type=SecurityEventType.DUPLICATE_EXECUTION_ATTEMPT,
                    severity=Severity.HIGH,
                    task_id=action.task_id,
                    action_id=action.action_id,
                    message="Agent attempted duplicate execution of an already-executed or in-flight action.",
                )
                blocked_decision = MonitoringDecision(
                    action_id=action.action_id,
                    task_id=action.task_id,
                    decision=Verdict.BLOCK,
                    severity=Severity.HIGH,
                    explanation="Action has already been executed or is currently in-flight. Duplicate execution is prohibited.",
                    evaluated_rules=["gateway-duplicate-execution-guard"],
                )
                if raise_on_blocked:
                    raise DuplicateExecutionError(blocked_decision.explanation)
                return ExecutionResult(
                    action_id=action.action_id,
                    executed=False,
                    success=False,
                    decision=blocked_decision,
                    error=blocked_decision.explanation,
                )

            # Check approval token replay (already consumed or currently in-flight)
            if approval_id and (approval_id in self._consumed_approvals or approval_id in self._in_flight_approvals):
                logger.error(
                    f"Approval replay blocked: Approval token '{approval_id}' was already consumed or is in-flight."
                )
                self._engine.event_emitter.emit(
                    event_type=SecurityEventType.APPROVAL_REPLAY_ATTEMPT,
                    severity=Severity.HIGH,
                    task_id=action.task_id,
                    action_id=action.action_id,
                    message=f"Approval token '{approval_id}' was already consumed or is in-flight. Replay blocked.",
                )
                replay_decision = MonitoringDecision(
                    action_id=action.action_id,
                    task_id=action.task_id,
                    decision=Verdict.BLOCK,
                    severity=Severity.HIGH,
                    explanation=f"Approval token '{approval_id}' has already been consumed. Replay attack blocked.",
                    evaluated_rules=["gateway-approval-replay-guard"],
                )
                if raise_on_blocked:
                    raise ApprovalReplayError(replay_decision.explanation)
                return ExecutionResult(
                    action_id=action.action_id,
                    executed=False,
                    success=False,
                    decision=replay_decision,
                    error=replay_decision.explanation,
                )

            # Atomically mark as in-flight before releasing lock for inspection
            self._in_flight_actions.add(action.action_id)
            if approval_id:
                self._in_flight_approvals.add(approval_id)

        try:
            # ── 2. Runtime Monitoring & Policy Inspection ─────────────
            decision = self._engine.inspect(action)

            # ── 3. Verdict Enforcement ────────────────────────────────
            if decision.decision == Verdict.BLOCK:
                with self._lock:
                    self._in_flight_actions.discard(action.action_id)
                    if approval_id:
                        self._in_flight_approvals.discard(approval_id)

                logger.warning(
                    f"Execution BLOCKED for action '{action.action_id}': {decision.explanation}"
                )
                if raise_on_blocked:
                    raise ExecutionBlockedError(decision.explanation)
                return ExecutionResult(
                    action_id=action.action_id,
                    executed=False,
                    success=False,
                    decision=decision,
                    error=f"Execution blocked by security policy: {decision.explanation}",
                )

            if decision.decision == Verdict.REQUIRE_APPROVAL:
                with self._lock:
                    self._in_flight_actions.discard(action.action_id)
                    if approval_id:
                        self._in_flight_approvals.discard(approval_id)

                logger.warning(
                    f"Execution PAUSED for action '{action.action_id}': human approval required."
                )
                if raise_on_blocked:
                    raise ApprovalRequiredError(decision.explanation)
                return ExecutionResult(
                    action_id=action.action_id,
                    executed=False,
                    success=False,
                    decision=decision,
                    error="Execution paused: explicit human approval is required before running this tool.",
                )

            # ── 4. Authorization & Tool Invocation (ALLOW) ────────────
            assert decision.decision == Verdict.ALLOW

            # Atomically commit authorization and approval consumption
            with self._lock:
                self._executed_actions.add(action.action_id)
                self._in_flight_actions.discard(action.action_id)
                if approval_id:
                    self._consumed_approvals.add(approval_id)
                    self._in_flight_approvals.discard(approval_id)

            try:
                logger.info(
                    f"Executing tool for authorized action '{action.action_id}' ({action.action_type.value})."
                )
                tool_output = tool_callable(*args, **kwargs)

                # Record successful execution in trajectory history
                self._engine.tracker.record_executed(
                    action.action_id, action.task_id, result=tool_output
                )
                self._engine.event_emitter.emit(
                    event_type=SecurityEventType.EXECUTION_SUCCESS,
                    severity=Severity.LOW,
                    task_id=action.task_id,
                    action_id=action.action_id,
                    message=f"Tool executed successfully for action '{action.action_id}'.",
                )

                return ExecutionResult(
                    action_id=action.action_id,
                    executed=True,
                    success=True,
                    decision=decision,
                    result=tool_output,
                    executed_at=datetime.now(timezone.utc),
                )

            except Exception as tool_exc:
                logger.error(
                    f"Underlying tool execution failed for action '{action.action_id}': {tool_exc}",
                    exc_info=True,
                )
                self._engine.tracker.record_executed(
                    action.action_id, action.task_id, error=str(tool_exc)
                )
                self._engine.event_emitter.emit(
                    event_type=SecurityEventType.EXECUTION_FAILURE,
                    severity=Severity.HIGH,
                    task_id=action.task_id,
                    action_id=action.action_id,
                    message=f"Underlying tool raised an exception: {tool_exc}",
                    details={"error": str(tool_exc)},
                )
                return ExecutionResult(
                    action_id=action.action_id,
                    executed=True,
                    success=False,  # Accurately reflect that execution failed
                    decision=decision,
                    error=f"Tool execution failed: {tool_exc}",
                    executed_at=datetime.now(timezone.utc),
                )

        except Exception as exc:
            # ── 5. Fail-Closed Gateway Guard ──────────────────────────
            with self._lock:
                self._in_flight_actions.discard(action.action_id)
                if approval_id:
                    self._in_flight_approvals.discard(approval_id)

            logger.critical(
                f"Gateway fail-closed: Unhandled exception during execution gating: {exc}",
                exc_info=True,
            )
            self._engine.event_emitter.emit(
                event_type=SecurityEventType.MONITORING_FAILURE,
                severity=Severity.CRITICAL,
                task_id=action.task_id,
                action_id=action.action_id,
                message=f"Execution gateway failed closed: {exc}",
                details={"error": str(exc)},
            )
            fail_decision = MonitoringDecision(
                action_id=action.action_id,
                task_id=action.task_id,
                decision=Verdict.BLOCK,
                severity=Severity.CRITICAL,
                explanation=f"Execution gateway internal error (failed closed): {exc}",
                evaluated_rules=["gateway-fail-closed"],
            )
            return ExecutionResult(
                action_id=action.action_id,
                executed=False,
                success=False,
                decision=fail_decision,
                error=fail_decision.explanation,
            )

    def is_action_executed(self, action_id: str) -> bool:
        """Check if an action ID has already been executed."""
        with self._lock:
            return action_id in self._executed_actions

    def is_approval_consumed(self, approval_id: str) -> bool:
        """Check if an approval ID has already been consumed."""
        with self._lock:
            return approval_id in self._consumed_approvals

    def clear(self) -> None:
        """Reset execution gateway records (test utility)."""
        with self._lock:
            self._executed_actions.clear()
            self._in_flight_actions.clear()
            self._consumed_approvals.clear()
            self._in_flight_approvals.clear()
