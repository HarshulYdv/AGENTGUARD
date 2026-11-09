"""Tests for mock HTTP services and mock database operations in AGENTGUARD simulator."""

from __future__ import annotations

import pytest

from backend.security.models import ActionType, TaskContext, Verdict
from backend.simulator.sandbox import SimulationSandbox


@pytest.fixture
def sandbox() -> SimulationSandbox:
    return SimulationSandbox()


@pytest.fixture
def service_task(sandbox: SimulationSandbox) -> TaskContext:
    task = TaskContext(
        task_id="task-sim-services-01",
        original_instruction="Query internal banking API and update audit database.",
        allowed_actions=[ActionType.READ, ActionType.WRITE, ActionType.EXECUTE, ActionType.DELETE],
        allowed_entities=[
            "https://api.banking.internal/v1/health",
            "db:audit_logs/log-001",
        ],
    )
    return sandbox.context_manager.create_task(task)


def test_mock_http_request(
    sandbox: SimulationSandbox, service_task: TaskContext
) -> None:
    """Mock HTTP service resolves pre-registered route without network calls."""
    res = sandbox.http_request(
        service_task.task_id, "GET", "https://api.banking.internal/v1/health"
    )
    assert res.executed is True
    assert res.decision.decision == Verdict.ALLOW
    assert res.result["status_code"] == 200
    assert res.result["body"]["status"] == "healthy"


def test_mock_database_crud(
    sandbox: SimulationSandbox, service_task: TaskContext
) -> None:
    """Mock database performs in-memory CRUD operations."""
    # 1. Write record
    res_w = sandbox.db_write(
        service_task.task_id,
        table="audit_logs",
        record_id="log-001",
        data={"event": "invoice_inspected", "severity": "low"},
    )
    assert res_w.executed is True
    assert res_w.decision.decision == Verdict.ALLOW

    # 2. Read record
    res_r = sandbox.db_read(
        service_task.task_id, table="audit_logs", record_id="log-001"
    )
    assert res_r.executed is True
    assert res_r.result["event"] == "invoice_inspected"

    # 3. Delete record
    res_d = sandbox.db_delete(
        service_task.task_id, table="audit_logs", record_id="log-001"
    )
    assert res_d.executed is True
    assert sandbox.state.get_table_record("audit_logs", "log-001") is None
