"""Deterministic fault injection engine for AGENTGUARD execution simulation.

Simulates tool-level runtime failures (timeouts, rate limits, 5xx server errors,
corrupted responses) AFTER policy authorization, allowing testing of agent recovery
and accurate TrajectoryTracker failure recording.
"""

from __future__ import annotations

import random
import threading
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FaultType(str, Enum):
    """Categorisation of simulated tool execution failures."""

    NETWORK_TIMEOUT = "network_timeout"
    RATE_LIMIT = "rate_limit"
    SERVER_ERROR = "server_error"
    CORRUPTED_RESPONSE = "corrupted_response"
    CONNECTION_RESET = "connection_reset"


class SimulatedFaultError(Exception):
    """Base exception for all simulated runtime faults."""
    pass


class SimulatedTimeoutError(SimulatedFaultError):
    """Simulated network timeout (e.g. gateway socket read timeout)."""
    pass


class SimulatedRateLimitError(SimulatedFaultError):
    """Simulated 429 Too Many Requests."""
    pass


class SimulatedServerError(SimulatedFaultError):
    """Simulated 500 / 503 Internal Server Error."""
    pass


class SimulatedCorruptionError(SimulatedFaultError):
    """Simulated payload corruption / schema decode failure."""
    pass


class FaultConfig(BaseModel):
    """Configuration for a deterministic or probabilistic fault rule."""

    rule_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this fault rule to avoid collision.",
    )
    fault_type: FaultType = Field(
        description="Type of fault to inject.",
    )
    probability: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Trigger probability (1.0 = fully deterministic).",
    )
    affected_tools: List[str] = Field(
        default_factory=list,
        description="Specific tool names affected (empty list applies to all tools).",
    )
    max_triggers: Optional[int] = Field(
        default=None,
        description="Maximum number of times this fault may fire before expiring.",
    )
    error_message: str = Field(
        default="",
        description="Custom error message override.",
    )


class FaultInjector:
    """Thread-safe controller for deterministic failure injection."""

    def __init__(self, seed: Optional[int] = 42) -> None:
        self._lock = threading.RLock()
        self._faults: List[FaultConfig] = []
        self._trigger_counts: Dict[str, int] = {}
        self._initial_seed = seed
        self._rng = random.Random(seed)

    def register_fault(self, fault: FaultConfig) -> None:
        with self._lock:
            self._faults.append(fault)

    def should_fault(self, tool_name: str) -> Optional[FaultConfig]:
        """Check if any registered fault rule matches the specified tool call."""
        with self._lock:
            for fault in self._faults:
                if fault.affected_tools and tool_name not in fault.affected_tools:
                    continue

                rule_key = f"{fault.rule_id}:{tool_name}"
                current_count = self._trigger_counts.get(rule_key, 0)
                if fault.max_triggers is not None and current_count >= fault.max_triggers:
                    continue

                if fault.probability >= 1.0 or self._rng.random() < fault.probability:
                    self._trigger_counts[rule_key] = current_count + 1
                    return fault
            return None

    def maybe_inject(self, tool_name: str) -> None:
        """Evaluate rules and raise simulated exception if triggered."""
        fault = self.should_fault(tool_name)
        if fault is None:
            return

        msg = fault.error_message or f"Simulated {fault.fault_type.value} on '{tool_name}'."
        if fault.fault_type == FaultType.NETWORK_TIMEOUT:
            raise SimulatedTimeoutError(msg)
        if fault.fault_type == FaultType.RATE_LIMIT:
            raise SimulatedRateLimitError(msg)
        if fault.fault_type == FaultType.SERVER_ERROR:
            raise SimulatedServerError(msg)
        if fault.fault_type == FaultType.CORRUPTED_RESPONSE:
            raise SimulatedCorruptionError(msg)
        if fault.fault_type == FaultType.CONNECTION_RESET:
            raise SimulatedFaultError(msg)
        raise SimulatedFaultError(msg)

    def reset(self) -> None:
        """Clear all registered faults, trigger counters, and re-seed the RNG."""
        with self._lock:
            self._faults.clear()
            self._trigger_counts.clear()
            self._rng = random.Random(self._initial_seed)

