"""Mock database operation tools and action builders for AGENTGUARD simulator.

Provides isolated key-value / document table operations in memory.
Does not interact with the host SQLite engine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.security.models import Action, ActionType
from backend.simulator.state import SimulationState


def build_db_read_action(task_id: str, table: str, record_id: str, **kwargs: Any) -> Action:
    return Action(
        task_id=task_id,
        action_type=ActionType.READ,
        target_entity=f"db:{table}/{record_id}",
        parameters={"table": table, "record_id": record_id, **kwargs},
    )


def build_db_write_action(
    task_id: str, table: str, record_id: str, data: Dict[str, Any], **kwargs: Any
) -> Action:
    return Action(
        task_id=task_id,
        action_type=ActionType.WRITE,
        target_entity=f"db:{table}/{record_id}",
        parameters={"table": table, "record_id": record_id, "data_keys": list(data.keys()), **kwargs},
    )


def build_db_delete_action(task_id: str, table: str, record_id: str, **kwargs: Any) -> Action:
    return Action(
        task_id=task_id,
        action_type=ActionType.DELETE,
        target_entity=f"db:{table}/{record_id}",
        parameters={"table": table, "record_id": record_id, **kwargs},
    )


def raw_db_read(
    state: SimulationState, task_id: str, table: str, record_id: str, **kwargs: Any
) -> Dict[str, Any]:
    rec = state.get_table_record(table, record_id)
    if rec is None:
        raise KeyError(f"Record '{record_id}' not found in table '{table}'.")
    return rec


def raw_db_write(
    state: SimulationState,
    task_id: str,
    table: str,
    record_id: str,
    data: Dict[str, Any],
    **kwargs: Any,
) -> Dict[str, Any]:
    state.set_table_record(table, record_id, data)
    return {"table": table, "record_id": record_id, "status": "saved"}


def raw_db_delete(
    state: SimulationState, task_id: str, table: str, record_id: str, **kwargs: Any
) -> Dict[str, Any]:
    deleted = state.delete_table_record(table, record_id)
    if not deleted:
        raise KeyError(f"Record '{record_id}' not found in table '{table}'.")
    return {"table": table, "record_id": record_id, "status": "deleted"}

