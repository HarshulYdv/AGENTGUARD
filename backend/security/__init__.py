"""Security subsystem module for AGENTGUARD.

Provides task-aware runtime security through structured task contexts,
deterministic policy evaluation, chronological trajectory tracking,
runtime monitoring, and gated tool execution.
"""

from backend.security.context import TaskContextManager
from backend.security.engine import PolicyEngine
from backend.security.events import (
    SecurityEvent,
    SecurityEventEmitter,
    SecurityEventType,
)
from backend.security.gateway import (
    ApprovalReplayError,
    DuplicateExecutionError,
    ExecutionBlockedError,
    ExecutionGateway,
    ExecutionResult,
    SecurityExecutionError,
)
from backend.security.interceptor import ActionInterceptor
from backend.security.models import (
    Action,
    ActionType,
    ApprovalRecord,
    ApprovalRequirement,
    Policy,
    PolicyDecision,
    PolicyRule,
    PolicyRuleType,
    Severity,
    TaskContext,
    TaskStatus,
    Verdict,
)
from backend.security.monitoring import MonitoringDecision, MonitoringEngine
from backend.security.tracker import (
    ActionRecord,
    AnomalyType,
    TrajectoryAnomaly,
    TrajectoryTracker,
)

__all__ = [
    # Models & Enumerations
    "Action",
    "ActionType",
    "ApprovalRecord",
    "ApprovalRequirement",
    "Policy",
    "PolicyDecision",
    "PolicyRule",
    "PolicyRuleType",
    "Severity",
    "TaskContext",
    "TaskStatus",
    "Verdict",
    # Context Management & Policy Evaluation
    "TaskContextManager",
    "PolicyEngine",
    # Runtime Monitoring & Trajectory Tracking (Stage 03)
    "ActionInterceptor",
    "ActionRecord",
    "AnomalyType",
    "ApprovalReplayError",
    "DuplicateExecutionError",
    "ExecutionBlockedError",
    "ExecutionGateway",
    "ExecutionResult",
    "MonitoringDecision",
    "MonitoringEngine",
    "SecurityEvent",
    "SecurityEventEmitter",
    "SecurityEventType",
    "SecurityExecutionError",
    "TrajectoryAnomaly",
    "TrajectoryTracker",
]
