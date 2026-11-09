"""Synthetic HTTP client tools and action builders for AGENTGUARD simulator.

Provides safe, deterministic HTTP request handling backed by the SimulationState route registry.
Never makes real outbound network calls.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.security.models import Action, ActionType
from backend.simulator.state import SimulationState


def build_http_request_action(
    task_id: str,
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Action:
    target = url if url.startswith("http:") or url.startswith("https:") else f"http:{url}"
    return Action(
        task_id=task_id,
        action_type=ActionType.EXECUTE,
        target_entity=target,
        parameters={"method": method.upper(), "url": url, "has_payload": payload is not None, **kwargs},
    )


def raw_http_request(
    state: SimulationState,
    task_id: str,
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    response = state.get_http_response(method, url)
    if response is None:
        return {
            "status_code": 404,
            "url": url,
            "method": method.upper(),
            "body": {"error": f"No mock route registered for {method.upper()} {url}"},
        }
    return {
        "status_code": response.get("status_code", 200),
        "url": url,
        "method": method.upper(),
        "body": response.get("body", response),
    }

