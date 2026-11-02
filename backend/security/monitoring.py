"""MonitoringEngine — Central runtime security and workflow inspection engine.

Coordinates task context resolution, chronological trajectory inspection,
policy rule evaluation, parameter validation, anomaly detection, and
event emission to produce a definitive, auditable MonitoringDecision.

SECURITY INVARIANT:
Fails closed: Any unexpected evaluation error or unhandled failure
deterministically results in a BLOCK decision with CRITICAL severity.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.core.logging import get_logger
from backend.security.context import TaskContextManager
from backend.security.engine import PolicyEngine
from backend.security.events import SecurityEventEmitter, SecurityEventType
from backend.security.models import Action, ActionType, Severity, TaskContext, Verdict
from backend.security.tracker import TrajectoryAnomaly, TrajectoryTracker

logger = get_logger("security.monitoring")


class MonitoringDecision(BaseModel):
    """Structured, auditable security decision produced by the MonitoringEngine."""

    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for this monitoring decision.",
    )
    action_id: str = Field(
        description="ID of the evaluated proposed action.",
    )
    task_id: str = Field(
        description="Task context ID under which the action was evaluated.",
    )
    decision: Verdict = Field(
        description="Authorization verdict: ALLOW, BLOCK, or REQUIRE_APPROVAL.",
    )
    severity: Severity = Field(
        description="Risk severity level associated with the decision.",
    )
    explanation: str = Field(
        description="Human-readable explanation and justification for the decision.",
    )
    evaluated_rules: List[str] = Field(
        default_factory=list,
        description="Identifiers of all policy and monitoring rules evaluated.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the monitoring decision was rendered.",
    )
    anomalies: List[str] = Field(
        default_factory=list,
        description="Descriptions of any trajectory or workflow anomalies detected.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional evaluation metadata, constraints, and audit info.",
    )

    @property
    def verdict(self) -> Verdict:
        """Alias for compatibility with PolicyDecision."""
        return self.decision


class MonitoringEngine:
    """Central runtime monitoring engine evaluating agent tool calls."""

    def __init__(
        self,
        context_manager: TaskContextManager,
        policy_engine: PolicyEngine,
        tracker: Optional[TrajectoryTracker] = None,
        event_emitter: Optional[SecurityEventEmitter] = None,
    ) -> None:
        self._ctx_mgr = context_manager
        self._policy_engine = policy_engine
        self._tracker = tracker or TrajectoryTracker()
        self._events = event_emitter or SecurityEventEmitter()

    @property
    def tracker(self) -> TrajectoryTracker:
        """Access the underlying trajectory tracker."""
        return self._tracker

    @property
    def event_emitter(self) -> SecurityEventEmitter:
        """Access the security event emitter."""
        return self._events

    def inspect(self, action: Action) -> MonitoringDecision:
        """Inspect a proposed action against context, history, and policies.

        Fails closed on any exception.
        """
        evaluated_rules: List[str] = []
        action_id = getattr(action, "action_id", "unknown")
        task_id = getattr(action, "task_id", "unknown")

        try:
            # ── 1. Action Payload Integrity Validation ─────────────────
            evaluated_rules.append("monitoring-action-integrity")
            if action is None or not isinstance(action, Action):
                return self._create_decision(
                    action_id=action_id,
                    task_id=task_id,
                    decision=Verdict.BLOCK,
                    severity=Severity.CRITICAL,
                    explanation="Proposed action is null or not a valid Action model.",
                    evaluated_rules=evaluated_rules,
                    emit_event=True,
                )

            # ── 2. Task Context Resolution ─────────────────────────────
            evaluated_rules.append("monitoring-context-resolution")
            task_context: Optional[TaskContext] = None
            if action.task_id and isinstance(action.task_id, str):
                task_context = self._ctx_mgr.get_task(action.task_id.strip())

            if task_context is None:
                return self._create_decision(
                    action_id=action.action_id,
                    task_id=action.task_id,
                    decision=Verdict.BLOCK,
                    severity=Severity.CRITICAL,
                    explanation=f"No valid task context found for task_id '{action.task_id}'.",
                    evaluated_rules=evaluated_rules,
                    emit_event=True,
                )

            # ── 3. Trajectory & Workflow Sequence Analysis ─────────────
            evaluated_rules.append("monitoring-trajectory-inspection")
            anomalies: List[TrajectoryAnomaly] = self._tracker.analyze_trajectory(
                action.task_id, action
            )

            # High severity anomalies trigger an immediate block or escalation
            for anomaly in anomalies:
                self._events.emit(
                    event_type=SecurityEventType.SUSPICIOUS_TRAJECTORY,
                    severity=anomaly.severity,
                    task_id=action.task_id,
                    message=f"Trajectory anomaly detected: {anomaly.description}",
                    action_id=action.action_id,
                    details=anomaly.details,
                )

            # Check if suspicious ordering was flagged on high-impact irreversible actions
            high_severity_ordering = [
                a for a in anomalies if a.severity in {Severity.HIGH, Severity.CRITICAL}
            ]
            if high_severity_ordering:
                # Ordering violations on transfer/delete must be blocked or paused
                ordering_reasons = "; ".join(a.description for a in high_severity_ordering)
                self._tracker.record_proposed(action, Verdict.BLOCK)
                return self._create_decision(
                    action_id=action.action_id,
                    task_id=action.task_id,
                    decision=Verdict.BLOCK,
                    severity=Severity.HIGH,
                    explanation=f"Workflow anomaly detected: {ordering_reasons}",
                    evaluated_rules=evaluated_rules,
                    anomalies=[a.description for a in anomalies],
                    emit_event=True,
                )

            # ── 4. Policy Engine Evaluation ────────────────────────────
            evaluated_rules.append("monitoring-policy-evaluation")
            policy_decision = self._policy_engine.evaluate(action)
            evaluated_rules.append(policy_decision.rule_id)

            # Record proposed action in trajectory tracker
            self._tracker.record_proposed(action, policy_decision.verdict)

            # ── 5. Generate Auditable Monitoring Decision ──────────────
            return self._create_decision(
                action_id=action.action_id,
                task_id=action.task_id,
                decision=policy_decision.verdict,
                severity=policy_decision.severity,
                explanation=policy_decision.reason,
                evaluated_rules=evaluated_rules,
                anomalies=[a.description for a in anomalies],
                metadata=policy_decision.evaluated_constraints,
                emit_event=True,
            )

        except Exception as exc:
            # ── FAIL CLOSED ───────────────────────────────────────────
            logger.critical(
                f"Fail-closed: Unhandled exception during monitoring evaluation: {exc}",
                exc_info=True,
            )
            self._events.emit(
                event_type=SecurityEventType.MONITORING_FAILURE,
                severity=Severity.CRITICAL,
                task_id=str(task_id),
                message=f"Monitoring engine failed closed due to error: {exc}",
                action_id=str(action_id),
                details={"error": str(exc)},
            )
            return self._create_decision(
                action_id=str(action_id),
                task_id=str(task_id),
                decision=Verdict.BLOCK,
                severity=Severity.CRITICAL,
                explanation=f"Monitoring engine internal error (failed closed): {exc}",
                evaluated_rules=evaluated_rules,
                emit_event=False,  # Already emitted above
            )

    def _create_decision(
        self,
        *,
        action_id: str,
        task_id: str,
        decision: Verdict,
        severity: Severity,
        explanation: str,
        evaluated_rules: List[str],
        anomalies: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        emit_event: bool = True,
    ) -> MonitoringDecision:
        """Construct the MonitoringDecision and emit corresponding security event."""
        mon_decision = MonitoringDecision(
            action_id=action_id,
            task_id=task_id,
            decision=decision,
            severity=severity,
            explanation=explanation,
            evaluated_rules=evaluated_rules,
            anomalies=anomalies or [],
            metadata=metadata or {},
        )

        if emit_event:
            event_type_map = {
                Verdict.ALLOW: SecurityEventType.ACTION_ALLOWED,
                Verdict.BLOCK: SecurityEventType.ACTION_BLOCKED,
                Verdict.REQUIRE_APPROVAL: SecurityEventType.APPROVAL_REQUIRED,
            }
            self._events.emit(
                event_type=event_type_map.get(decision, SecurityEventType.ACTION_BLOCKED),
                severity=severity,
                task_id=task_id,
                message=f"Decision rendered: {decision.value}. {explanation}",
                action_id=action_id,
                details={
                    "decision_id": mon_decision.decision_id,
                    "evaluated_rules": evaluated_rules,
                    "anomalies": anomalies or [],
                },
            )

        return mon_decision

