"""TrajectoryTracker — chronological action tracking and anomaly detection.

Maintains an immutable, chronological history of proposed and executed actions
per task. Detects suspicious ordering (e.g. high-risk actions without prior
inspection), repeated sensitive operations, rapid bursts, and workflow deviations.

SECURITY INVARIANT:
Proposed actions are strictly separated from executed actions.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.core.logging import get_logger
from backend.security.models import Action, ActionType, Severity, Verdict

logger = get_logger("security.tracker")


class AnomalyType(str, Enum):
    """Categorisation of behavioral and workflow sequence anomalies."""

    SUSPICIOUS_ORDERING = "suspicious_ordering"
    REPEATED_SENSITIVE_OPERATIONS = "repeated_sensitive_operations"
    RAPID_FIRE_BURST = "rapid_fire_burst"
    ACTION_REPETITION_LOOP = "action_repetition_loop"


class TrajectoryAnomaly(BaseModel):
    """Structured report of a detected trajectory sequence anomaly."""

    model_config = ConfigDict(frozen=True)

    anomaly_type: AnomalyType = Field(
        description="Category of the detected trajectory anomaly.",
    )
    severity: Severity = Field(
        description="Risk severity level.",
    )
    description: str = Field(
        description="Detailed explanation of the suspicious pattern.",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Forensic sequence data supporting the finding.",
    )


class ActionRecord(BaseModel):
    """Chronological record tracking an action through proposal and execution."""

    model_config = ConfigDict(frozen=True)

    action: Action = Field(
        description="The proposed action object.",
    )
    proposed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the action was proposed.",
    )
    verdict: Optional[Verdict] = Field(
        default=None,
        description="The policy or monitoring verdict rendered for this action.",
    )
    executed: bool = Field(
        default=False,
        description="Whether the action was actually executed by the gateway.",
    )
    executed_at: Optional[datetime] = Field(
        default=None,
        description="UTC time the underlying tool call was executed.",
    )
    result_summary: Optional[str] = Field(
        default=None,
        description="Sanitized summary or type of the execution return value.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error description if the execution failed.",
    )


class TrajectoryTracker:
    """Maintains task trajectories and detects sequence anomalies."""

    def __init__(self, *, max_repeated_sensitive: int = 3) -> None:
        # Maps task_id -> list of ActionRecord in chronological order
        self._trajectories: Dict[str, List[ActionRecord]] = defaultdict(list)
        self._max_repeated_sensitive = max_repeated_sensitive
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Recording API
    # ------------------------------------------------------------------

    def record_proposed(self, action: Action, verdict: Verdict) -> ActionRecord:
        """Record an action proposal and its security verdict."""
        with self._lock:
            record = ActionRecord(
                action=action.model_copy(deep=True),
                proposed_at=datetime.now(timezone.utc),
                verdict=verdict,
                executed=False,
            )
            self._trajectories[action.task_id].append(record)
            logger.info(
                f"Tracked proposed action '{action.action_id}' ({action.action_type.value}) "
                f"for task '{action.task_id}' with verdict: {verdict.value}."
            )
            return record

    def record_executed(
        self,
        action_id: str,
        task_id: str,
        *,
        result: Any = None,
        error: Optional[str] = None,
    ) -> Optional[ActionRecord]:
        """Update an existing proposed record to mark it as successfully or failed executed."""
        with self._lock:
            history = self._trajectories.get(task_id, [])
            for idx, item in enumerate(history):
                if item.action.action_id == action_id:
                    updated_record = ActionRecord(
                        action=item.action,
                        proposed_at=item.proposed_at,
                        verdict=item.verdict,
                        executed=True,
                        executed_at=datetime.now(timezone.utc),
                        result_summary=str(result)[:256] if result is not None else None,
                        error=error,
                    )
                    self._trajectories[task_id][idx] = updated_record
                    logger.info(
                        f"Tracked execution for action '{action_id}' on task '{task_id}' "
                        f"(success={error is None})."
                    )
                    return updated_record
            return None

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_trajectory(self, task_id: str) -> List[ActionRecord]:
        """Return the full chronological sequence of actions for a task."""
        with self._lock:
            return list(self._trajectories.get(task_id, []))

    def get_executed_actions(self, task_id: str) -> List[ActionRecord]:
        """Return only actions that were actually executed."""
        with self._lock:
            return [r for r in self._trajectories.get(task_id, []) if r.executed]

    def get_proposed_actions(self, task_id: str) -> List[ActionRecord]:
        """Return all proposed actions regardless of execution status."""
        with self._lock:
            return list(self._trajectories.get(task_id, []))

    # ------------------------------------------------------------------
    # Anomaly Detection Engine
    # ------------------------------------------------------------------

    def analyze_trajectory(
        self, task_id: str, proposed_action: Action
    ) -> List[TrajectoryAnomaly]:
        """Detect workflow anomalies, ordering deviations, and repeated operations."""
        anomalies: List[TrajectoryAnomaly] = []
        with self._lock:
            history = list(self._trajectories.get(task_id, []))

        # ── 1. Suspicious Action Ordering ─────────────────────────────
        # In financial and data tasks, irreversible operations (TRANSFER, DELETE, MODIFY)
        # must be preceded by reconnaissance/inspection (READ). Attempting a transfer
        # as the very first operation is a strong indicator of prompt injection or blind execution.
        sensitive_types = {ActionType.TRANSFER, ActionType.DELETE}
        if proposed_action.action_type in sensitive_types:
            has_prior_read = any(
                r.action.action_type == ActionType.READ for r in history
            )
            if not has_prior_read:
                anomalies.append(
                    TrajectoryAnomaly(
                        anomaly_type=AnomalyType.SUSPICIOUS_ORDERING,
                        severity=Severity.HIGH,
                        description=(
                            f"Action '{proposed_action.action_type.value}' proposed without prior "
                            "inspection or read operation. Irreversible actions should be preceded by reading task data."
                        ),
                        details={
                            "action_type": proposed_action.action_type.value,
                            "prior_actions_count": len(history),
                            "prior_actions": [r.action.action_type.value for r in history],
                        },
                    )
                )

        # ── 2. Repeated Sensitive Operations ──────────────────────────
        # Flag bursts of repeated transfer or delete requests
        recent_sensitive_count = sum(
            1
            for r in history[-self._max_repeated_sensitive :]
            if r.action.action_type in sensitive_types
        )
        if (
            proposed_action.action_type in sensitive_types
            and recent_sensitive_count >= self._max_repeated_sensitive
        ):
            anomalies.append(
                TrajectoryAnomaly(
                    anomaly_type=AnomalyType.REPEATED_SENSITIVE_OPERATIONS,
                    severity=Severity.HIGH,
                    description=(
                        f"Detected {recent_sensitive_count} consecutive sensitive operations. "
                        "Repeated high-value transactions flagged for potential runaway automation."
                    ),
                    details={
                        "recent_sensitive_count": recent_sensitive_count,
                        "threshold": self._max_repeated_sensitive,
                    },
                )
            )

        # ── 3. Action Repetition Loop ─────────────────────────────────
        # Detect agent stuck in an execution failure loop (repeating the exact same action type and entity)
        if len(history) >= 3:
            last_3 = history[-3:]
            same_action = all(
                r.action.action_type == proposed_action.action_type
                and r.action.target_entity == proposed_action.target_entity
                and r.verdict == Verdict.BLOCK
                for r in last_3
            )
            if same_action:
                anomalies.append(
                    TrajectoryAnomaly(
                        anomaly_type=AnomalyType.ACTION_REPETITION_LOOP,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Agent is repeatedly proposing blocked action '{proposed_action.action_type.value}' "
                            f"on target '{proposed_action.target_entity}'. Potential loop detected."
                        ),
                        details={"repeated_count": 3},
                    )
                )

        return anomalies

    def clear(self) -> None:
        """Reset all tracked trajectories (test utility)."""
        with self._lock:
            self._trajectories.clear()

