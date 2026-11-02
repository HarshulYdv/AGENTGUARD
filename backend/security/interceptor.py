"""ActionInterceptor — Central interception interface for autonomous agent tool calls.

Ensures that no agent tool or action executes directly. All invocations are
intercepted, validated, and gated through the ExecutionGateway.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

from backend.core.logging import get_logger
from backend.security.gateway import ExecutionGateway, ExecutionResult
from backend.security.models import Action, ActionType

logger = get_logger("security.interceptor")


class ActionInterceptor:
    """Central interface for intercepting, inspecting, and gating tool calls."""

    def __init__(self, gateway: ExecutionGateway) -> None:
        self._gateway = gateway

    @property
    def gateway(self) -> ExecutionGateway:
        """Access the underlying execution gateway."""
        return self._gateway

    def intercept(
        self,
        action: Action,
        tool_callable: Callable[..., Any],
        *args: Any,
        raise_on_blocked: bool = False,
        **kwargs: Any,
    ) -> ExecutionResult:
        """Intercept a proposed action and route it through security gating.

        CORE INVARIANT:
        The tool callable is invoked if and only if the gateway renders an ALLOW decision.
        """
        logger.info(
            f"Intercepting tool call for action '{action.action_id}' "
            f"({action.action_type.value} -> '{action.target_entity}')."
        )
        return self._gateway.execute(
            action,
            tool_callable,
            *args,
            raise_on_blocked=raise_on_blocked,
            **kwargs,
        )

    def wrap_tool(
        self,
        tool_callable: Callable[..., Any],
        action_builder: Callable[..., Action],
    ) -> Callable[..., ExecutionResult]:
        """Wrap an existing tool function to automatically enforce interception."""

        @wraps(tool_callable)
        def secured_wrapper(*args: Any, **kwargs: Any) -> ExecutionResult:
            action = action_builder(*args, **kwargs)
            return self.intercept(action, tool_callable, *args, **kwargs)

        return secured_wrapper

