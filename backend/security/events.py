"""Security Event Handling subsystem for AGENTGUARD.

Produces structured, auditable security events for all runtime decisions,
violations, anomalies, approval requests, and execution outcomes.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.core.logging import get_logger
from backend.security.models import Severity

logger = get_logger("security.events")


class SecurityEventType(str, Enum):
    """Categorisation of security-relevant runtime events."""

    ACTION_ALLOWED = "action_allowed"
    ACTION_BLOCKED = "action_blocked"
    APPROVAL_REQUIRED = "approval_required"
    SUSPICIOUS_TRAJECTORY = "suspicious_trajectory"
    DUPLICATE_EXECUTION_ATTEMPT = "duplicate_execution_attempt"
    APPROVAL_REPLAY_ATTEMPT = "approval_replay_attempt"
    EXECUTION_SUCCESS = "execution_success"
    EXECUTION_FAILURE = "execution_failure"
    MONITORING_FAILURE = "monitoring_failure"


class SecurityEvent(BaseModel):
    """Structured, immutable audit event record."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for this security event.",
    )
    event_type: SecurityEventType = Field(
        description="Category of the security event.",
    )
    severity: Severity = Field(
        description="Assigned risk severity level.",
    )
    task_id: str = Field(
        description="Associated task context ID.",
    )
    action_id: Optional[str] = Field(
        default=None,
        description="Associated proposed action ID, if applicable.",
    )
    message: str = Field(
        description="Human-readable explanation of the security event.",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured forensic metadata, constraints, and audit data.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the event was generated.",
    )


class SecurityEventEmitter:
    """Thread-safe event emitter maintaining an append-only in-memory log."""

    def __init__(self) -> None:
        self._events: List[SecurityEvent] = []
        self._subscribers: List[Callable[[SecurityEvent], None]] = []
        self._lock = threading.RLock()

    def emit(
        self,
        event_type: SecurityEventType,
        severity: Severity,
        task_id: str,
        message: str,
        *,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """Create and emit a new security event."""
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            task_id=task_id,
            action_id=action_id,
            message=message,
            details=details or {},
        )

        with self._lock:
            self._events.append(event)
            subscribers_snapshot = list(self._subscribers)

        log_level_map = {
            Severity.LOW: logger.info,
            Severity.MEDIUM: logger.warning,
            Severity.HIGH: logger.error,
            Severity.CRITICAL: logger.critical,
        }
        log_func = log_level_map.get(severity, logger.info)
        log_func(f"[{event_type.value.upper()}] Task: '{task_id}' - {message}")

        for subscriber in subscribers_snapshot:
            try:
                subscriber(event)
            except Exception as exc:
                logger.error(f"Event subscriber failed: {exc}", exc_info=True)

        return event

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback to receive emitted events in real-time."""
        with self._lock:
            self._subscribers.append(callback)

    def get_events(
        self,
        *,
        task_id: Optional[str] = None,
        event_type: Optional[SecurityEventType] = None,
        min_severity: Optional[Severity] = None,
    ) -> List[SecurityEvent]:
        """Query historical audit events with optional filters."""
        severity_rank = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        with self._lock:
            results = list(self._events)

        if task_id is not None:
            results = [e for e in results if e.task_id == task_id]
        if event_type is not None:
            results = [e for e in results if e.event_type == event_type]
        if min_severity is not None:
            target_rank = severity_rank.get(min_severity, 1)
            results = [
                e for e in results if severity_rank.get(e.severity, 1) >= target_rank
            ]
        return list(results)

    def clear(self) -> None:
        """Clear recorded events (test utility)."""
        with self._lock:
            self._events.clear()

