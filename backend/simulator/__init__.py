"""Simulator subsystem module for AGENTGUARD.

Provides execution sandboxes, mock tools, synthetic financial entities,
deterministic fault injection, and adversarial regression replay in Stage 04.
"""

from backend.simulator.approval import ApprovalService
from backend.simulator.faults import (
    FaultConfig,
    FaultInjector,
    FaultType,
    SimulatedCorruptionError,
    SimulatedFaultError,
    SimulatedRateLimitError,
    SimulatedServerError,
    SimulatedTimeoutError,
)
from backend.simulator.models import (
    BankAccount,
    Invoice,
    InvoiceStatus,
    Payment,
    PaymentStatus,
    Vendor,
)
from backend.simulator.runner import SandboxRunner, ScenarioResult
from backend.simulator.sandbox import SimulationSandbox
from backend.simulator.scenarios import (
    AdversarialScenario,
    ScenarioCategory,
    build_forged_approval_scenario,
    build_legitimate_approved_workflow_scenario,
    build_limit_breach_scenario,
    build_sanctioned_payment_scenario,
    build_self_modification_scenario,
    get_standard_scenarios,
)
from backend.simulator.seed import create_default_state, populate_default_state
from backend.simulator.state import SimulationState

__all__ = [
    # Data Models
    "BankAccount",
    "Vendor",
    "Invoice",
    "InvoiceStatus",
    "Payment",
    "PaymentStatus",
    # State & Seed
    "SimulationState",
    "create_default_state",
    "populate_default_state",
    # Sandbox & Approval
    "SimulationSandbox",
    "ApprovalService",
    # Fault Injection
    "FaultType",
    "FaultConfig",
    "FaultInjector",
    "SimulatedFaultError",
    "SimulatedTimeoutError",
    "SimulatedRateLimitError",
    "SimulatedServerError",
    "SimulatedCorruptionError",
    # Scenarios & Runner
    "AdversarialScenario",
    "ScenarioCategory",
    "SandboxRunner",
    "ScenarioResult",
    "get_standard_scenarios",
    "build_sanctioned_payment_scenario",
    "build_limit_breach_scenario",
    "build_forged_approval_scenario",
    "build_self_modification_scenario",
    "build_legitimate_approved_workflow_scenario",
]
