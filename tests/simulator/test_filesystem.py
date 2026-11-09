"""Tests for virtual filesystem operations and path traversal security in AGENTGUARD simulator."""

from __future__ import annotations

import pytest

from backend.security.models import ActionType, TaskContext, Verdict
from backend.simulator.sandbox import SimulationSandbox
from backend.simulator.tools.filesystem import (
    PathTraversalError,
    build_read_file_action,
    build_write_file_action,
    normalize_sandbox_path,
    raw_list_dir,
)


@pytest.fixture
def sandbox() -> SimulationSandbox:
    return SimulationSandbox()


@pytest.fixture
def fs_task(sandbox: SimulationSandbox) -> TaskContext:
    task = TaskContext(
        task_id="task-sim-fs-01",
        original_instruction="Manage workspace documents and summaries.",
        allowed_actions=[ActionType.READ, ActionType.WRITE, ActionType.DELETE],
        allowed_entities=[
            "file:/workspace/invoices/summary.json",
            "file:/workspace/notes/policy_reminder.txt",
            "file:/workspace/reports/output.txt",
            "dir:/workspace/",
        ],
    )
    return sandbox.context_manager.create_task(task)


def test_read_and_write_sandboxed_file(
    sandbox: SimulationSandbox, fs_task: TaskContext
) -> None:
    """Read existing virtual file and write new file within sandbox."""
    # 1. Read baseline file
    read_res = sandbox.read_file(fs_task.task_id, "/workspace/invoices/summary.json")
    assert read_res.executed is True
    assert read_res.decision.decision == Verdict.ALLOW
    assert "pending_invoices_count" in read_res.result

    # 2. Write new file
    write_res = sandbox.write_file(
        fs_task.task_id, "/workspace/reports/output.txt", "Audit Completed Successfully."
    )
    assert write_res.executed is True
    assert write_res.decision.decision == Verdict.ALLOW

    # Verify content in state
    saved_bytes = sandbox.state.get_file("/workspace/reports/output.txt")
    assert saved_bytes == b"Audit Completed Successfully."


def test_delete_sandboxed_file(
    sandbox: SimulationSandbox, fs_task: TaskContext
) -> None:
    """Delete a virtual file within allowed sandbox root (preceded by inspection read)."""
    # 1. Prerequisite read to satisfy trajectory ordering constraints
    read_res = sandbox.read_file(
        fs_task.task_id, "/workspace/notes/policy_reminder.txt"
    )
    assert read_res.executed is True

    # 2. Delete file
    del_res = sandbox.delete_file(
        fs_task.task_id, "/workspace/notes/policy_reminder.txt"
    )
    assert del_res.executed is True
    assert del_res.decision.decision == Verdict.ALLOW
    assert sandbox.state.get_file("/workspace/notes/policy_reminder.txt") is None


def test_path_traversal_attack_blocked(
    sandbox: SimulationSandbox, fs_task: TaskContext
) -> None:
    """Path traversal attempt outside sandbox root (/etc/shadow) is stopped."""
    res = sandbox.read_file(fs_task.task_id, "/etc/shadow")
    # Blocked by allowed_entities whitelist in PolicyEngine
    assert res.executed is False
    assert res.decision.decision == Verdict.BLOCK


# ==============================================================================
# Remediation Regression Tests (SEC-04-005 & SEC-04-006)
# ==============================================================================

def test_normalize_sandbox_path_exact_roots() -> None:
    """SEC-04-005: Roots without trailing slashes must normalize and be accepted."""
    assert normalize_sandbox_path("/workspace") == "/workspace"
    assert normalize_sandbox_path("/tmp") == "/tmp"
    assert normalize_sandbox_path("\\workspace") == "/workspace"


def test_normalize_sandbox_path_rejects_prefix_collisions() -> None:
    """SEC-04-005: Prefix collisions like /workspace_evil must be rejected."""
    with pytest.raises(PathTraversalError):
        normalize_sandbox_path("/workspace_evil/secret.txt")

    with pytest.raises(PathTraversalError):
        normalize_sandbox_path("/tmp_evil")

    with pytest.raises(PathTraversalError):
        normalize_sandbox_path("/workspace/../../etc/passwd")


def test_action_builders_canonicalize_target_entity() -> None:
    """SEC-04-006: Target entities in Action objects must be canonicalized."""
    # Dot segment elimination
    act = build_read_file_action("task-fs-norm", "/workspace/sub/../test.txt")
    assert act.target_entity == "file:/workspace/test.txt"
    assert act.parameters["path"] == "/workspace/test.txt"
    assert act.parameters["requested_path"] == "/workspace/sub/../test.txt"

    # Windows backslash normalization
    act_win = build_write_file_action("task-fs-norm", "\\workspace\\notes\\todo.txt", "data")
    assert act_win.target_entity == "file:/workspace/notes/todo.txt"
    assert act_win.parameters["path"] == "/workspace/notes/todo.txt"
    assert act_win.parameters["requested_path"] == "\\workspace\\notes\\todo.txt"


def test_list_dir_without_trailing_slash(sandbox: SimulationSandbox) -> None:
    """SEC-04-005: raw_list_dir works when root is passed without trailing slash."""
    files = raw_list_dir(sandbox.state, "task-list", "/workspace")
    assert any("summary.json" in f for f in files)
