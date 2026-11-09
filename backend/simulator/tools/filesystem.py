"""Virtual filesystem tool operations and action builders for AGENTGUARD simulator.

Provides an isolated, in-memory sandboxed filesystem with path normalization
and directory traversal defenses.
"""

from __future__ import annotations

import posixpath
from typing import Any, Dict, List, Optional

from backend.security.models import Action, ActionType
from backend.simulator.state import SimulationState

DEFAULT_ALLOWED_ROOTS = ("/workspace", "/tmp")
DEFAULT_ALLOWED_PREFIXES = ("/workspace/", "/tmp/", "/workspace", "/tmp")


class PathTraversalError(PermissionError):
    """Raised when an agent attempts to access a path outside sandboxed roots."""
    pass


def canonicalize_path(path: str) -> str:
    """Canonicalize a path by normalizing separators and dot segments.

    Ensures POSIX style and absolute leading slash.
    Strips 'file:' or 'dir:' prefix if present.
    """
    clean_input = path.removeprefix("file:").removeprefix("dir:")
    clean_path = posixpath.normpath(clean_input.replace("\\", "/"))
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path
    return clean_path


def is_within_sandbox(
    clean_path: str,
    allowed_roots: tuple[str, ...] = DEFAULT_ALLOWED_ROOTS,
) -> bool:
    """Check if clean_path is strictly within or equal to one of the allowed roots."""
    for root in allowed_roots:
        clean_root = root.rstrip("/")
        if clean_path == clean_root or clean_path.startswith(clean_root + "/"):
            return True
    return False


def normalize_sandbox_path(
    path: str,
    allowed_prefixes: tuple[str, ...] = DEFAULT_ALLOWED_ROOTS,
) -> str:
    """Normalize POSIX-style path and ensure it is confined within an allowed sandbox root."""
    clean_path = canonicalize_path(path)
    if not is_within_sandbox(clean_path, allowed_prefixes):
        raise PathTraversalError(
            f"Path '{path}' resolves to '{clean_path}', outside allowed sandboxed roots: {allowed_prefixes}"
        )
    return clean_path


# ==============================================================================
# Action Builders
# ==============================================================================

def build_read_file_action(task_id: str, path: str, **kwargs: Any) -> Action:
    canon = canonicalize_path(path)
    return Action(
        task_id=task_id,
        action_type=ActionType.READ,
        target_entity=f"file:{canon}",
        parameters={"path": canon, "requested_path": path, **kwargs},
    )


def build_write_file_action(task_id: str, path: str, content: str, **kwargs: Any) -> Action:
    canon = canonicalize_path(path)
    return Action(
        task_id=task_id,
        action_type=ActionType.WRITE,
        target_entity=f"file:{canon}",
        parameters={"path": canon, "requested_path": path, "content_size": len(content), **kwargs},
    )


def build_delete_file_action(task_id: str, path: str, **kwargs: Any) -> Action:
    canon = canonicalize_path(path)
    return Action(
        task_id=task_id,
        action_type=ActionType.DELETE,
        target_entity=f"file:{canon}",
        parameters={"path": canon, "requested_path": path, **kwargs},
    )


def build_list_dir_action(task_id: str, directory: str, **kwargs: Any) -> Action:
    canon = canonicalize_path(directory)
    return Action(
        task_id=task_id,
        action_type=ActionType.READ,
        target_entity=f"dir:{canon}",
        parameters={"directory": canon, "requested_directory": directory, **kwargs},
    )


# ==============================================================================
# Raw Operations (operating on SimulationState)
# ==============================================================================

def raw_read_file(state: SimulationState, task_id: str, path: str, **kwargs: Any) -> str:
    norm_path = normalize_sandbox_path(path)
    content_bytes = state.get_file(norm_path)
    if content_bytes is None:
        raise FileNotFoundError(f"Virtual file '{path}' does not exist.")
    return content_bytes.decode("utf-8", errors="replace")


def raw_write_file(
    state: SimulationState, task_id: str, path: str, content: str, **kwargs: Any
) -> Dict[str, Any]:
    norm_path = normalize_sandbox_path(path)
    encoded = content.encode("utf-8")
    state.set_file(norm_path, encoded)
    return {"path": norm_path, "bytes_written": len(encoded), "status": "written"}


def raw_delete_file(state: SimulationState, task_id: str, path: str, **kwargs: Any) -> Dict[str, Any]:
    norm_path = normalize_sandbox_path(path)
    deleted = state.delete_file(norm_path)
    if not deleted:
        raise FileNotFoundError(f"Virtual file '{path}' does not exist.")
    return {"path": norm_path, "status": "deleted"}


def raw_list_dir(state: SimulationState, task_id: str, directory: str, **kwargs: Any) -> List[str]:
    norm_dir = normalize_sandbox_path(directory)
    if not norm_dir.endswith("/"):
        norm_dir += "/"
    all_files = state.list_files(prefix=norm_dir)
    return [f.removeprefix(norm_dir) for f in all_files]

