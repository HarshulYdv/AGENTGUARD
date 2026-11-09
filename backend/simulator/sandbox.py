"""SimulationSandbox — Central execution sandbox wiring simulator tools to AGENTGUARD.

Enforces that every agent-facing tool call is strictly intercepted and gated through
the ActionInterceptor and ExecutionGateway. Provides a complete, resettable testbed.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.security.context import TaskContextManager
from backend.security.engine import PolicyEngine
from backend.security.events import SecurityEventEmitter
from backend.security.gateway import ExecutionGateway, ExecutionResult
from backend.security.interceptor import ActionInterceptor
from backend.security.models import Action, ActionType
from backend.security.monitoring import MonitoringEngine
from backend.security.tracker import TrajectoryTracker
from backend.simulator.approval import ApprovalService
from backend.simulator.faults import FaultInjector
from backend.simulator.seed import create_default_state, populate_default_state
from backend.simulator.state import SimulationState
from backend.simulator.tools.banking import (
    build_execute_payment_action,
    build_prepare_payment_action,
    build_read_account_action,
    build_read_invoice_action,
    raw_execute_payment,
    raw_prepare_payment,
    raw_read_account,
    raw_read_invoice,
)
from backend.simulator.tools.database import (
    build_db_delete_action,
    build_db_read_action,
    build_db_write_action,
    raw_db_delete,
    raw_db_read,
    raw_db_write,
)
from backend.simulator.tools.filesystem import (
    build_delete_file_action,
    build_list_dir_action,
    build_read_file_action,
    build_write_file_action,
    raw_delete_file,
    raw_list_dir,
    raw_read_file,
    raw_write_file,
)
from backend.simulator.tools.http_client import (
    build_http_request_action,
    raw_http_request,
)


class SimulationSandbox:
    """Integrated execution sandbox providing secured simulator tools."""

    def __init__(
        self,
        *,
        state: Optional[SimulationState] = None,
        context_manager: Optional[TaskContextManager] = None,
        fault_injector: Optional[FaultInjector] = None,
    ) -> None:
        self.state = state or create_default_state()
        self.fault_injector = fault_injector or FaultInjector()
        self.context_manager = context_manager or TaskContextManager()
        self.policy_engine = PolicyEngine(context_manager=self.context_manager)
        self.tracker = TrajectoryTracker()
        self.events = SecurityEventEmitter()
        self.monitoring_engine = MonitoringEngine(
            context_manager=self.context_manager,
            policy_engine=self.policy_engine,
            tracker=self.tracker,
            event_emitter=self.events,
        )
        self.gateway = ExecutionGateway(monitoring_engine=self.monitoring_engine)
        self.interceptor = ActionInterceptor(gateway=self.gateway)
        self.approvals = ApprovalService(context_manager=self.context_manager)

        # Wire secured tools
        self._wire_tools()

    def _wire_tools(self) -> None:
        """Wrap each raw simulator operation through ActionInterceptor."""
        # 1. Banking tools
        def _guarded_read_account(task_id: str, account_id: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("read_account")
            return raw_read_account(self.state, task_id, account_id, **kw)

        self.read_account = self.interceptor.wrap_tool(
            _guarded_read_account, build_read_account_action
        )

        def _guarded_read_invoice(task_id: str, invoice_id: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("read_invoice")
            return raw_read_invoice(self.state, task_id, invoice_id, **kw)

        self.read_invoice = self.interceptor.wrap_tool(
            _guarded_read_invoice, build_read_invoice_action
        )

        def _guarded_prepare_payment(
            task_id: str,
            from_account_id: str,
            to_vendor_id: str,
            amount: float,
            invoice_id: Optional[str] = None,
            **kw: Any,
        ) -> Any:
            self.fault_injector.maybe_inject("prepare_payment")
            return raw_prepare_payment(
                self.state, task_id, from_account_id, to_vendor_id, amount, invoice_id, **kw
            )

        self.prepare_payment = self.interceptor.wrap_tool(
            _guarded_prepare_payment, build_prepare_payment_action
        )

        def _guarded_execute_payment(
            task_id: str,
            from_account_id: str,
            to_vendor_id: str,
            amount: float,
            approval_id: Optional[str] = None,
            invoice_id: Optional[str] = None,
            **kw: Any,
        ) -> Any:
            self.fault_injector.maybe_inject("execute_payment")
            return raw_execute_payment(
                self.state,
                task_id,
                from_account_id,
                to_vendor_id,
                amount,
                approval_id,
                invoice_id,
                **kw,
            )

        self.execute_payment = self.interceptor.wrap_tool(
            _guarded_execute_payment, build_execute_payment_action
        )

        # 2. Virtual Filesystem tools
        def _guarded_read_file(task_id: str, path: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("read_file")
            return raw_read_file(self.state, task_id, path, **kw)

        self.read_file = self.interceptor.wrap_tool(
            _guarded_read_file, build_read_file_action
        )

        def _guarded_write_file(task_id: str, path: str, content: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("write_file")
            return raw_write_file(self.state, task_id, path, content, **kw)

        self.write_file = self.interceptor.wrap_tool(
            _guarded_write_file, build_write_file_action
        )

        def _guarded_delete_file(task_id: str, path: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("delete_file")
            return raw_delete_file(self.state, task_id, path, **kw)

        self.delete_file = self.interceptor.wrap_tool(
            _guarded_delete_file, build_delete_file_action
        )

        def _guarded_list_dir(task_id: str, directory: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("list_dir")
            return raw_list_dir(self.state, task_id, directory, **kw)

        self.list_dir = self.interceptor.wrap_tool(
            _guarded_list_dir, build_list_dir_action
        )

        # 3. HTTP Client tools
        def _guarded_http_request(
            task_id: str,
            method: str,
            url: str,
            payload: Optional[Dict[str, Any]] = None,
            **kw: Any,
        ) -> Any:
            self.fault_injector.maybe_inject("http_request")
            return raw_http_request(self.state, task_id, method, url, payload, **kw)

        self.http_request = self.interceptor.wrap_tool(
            _guarded_http_request, build_http_request_action
        )

        # 4. Mock Database tools
        def _guarded_db_read(task_id: str, table: str, record_id: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("db_read")
            return raw_db_read(self.state, task_id, table, record_id, **kw)

        self.db_read = self.interceptor.wrap_tool(
            _guarded_db_read, build_db_read_action
        )

        def _guarded_db_write(
            task_id: str, table: str, record_id: str, data: Dict[str, Any], **kw: Any
        ) -> Any:
            self.fault_injector.maybe_inject("db_write")
            return raw_db_write(self.state, task_id, table, record_id, data, **kw)

        self.db_write = self.interceptor.wrap_tool(
            _guarded_db_write, build_db_write_action
        )

        def _guarded_db_delete(task_id: str, table: str, record_id: str, **kw: Any) -> Any:
            self.fault_injector.maybe_inject("db_delete")
            return raw_db_delete(self.state, task_id, table, record_id, **kw)

        self.db_delete = self.interceptor.wrap_tool(
            _guarded_db_delete, build_db_delete_action
        )

    def reset(self, reseed: bool = True) -> None:
        """Reset state, tracker, events, fault injector, and gateway caches."""
        if reseed:
            populate_default_state(self.state)
        else:
            self.state.clear()
        self.fault_injector.reset()
        self.context_manager.clear()
        self.tracker.clear()
        self.events.clear()
        self.gateway.clear()

    def resolve_tool_for_action(
        self, action: Action
    ) -> Tuple[Callable[..., Any], Tuple[Any, ...], Dict[str, Any]]:
        """Resolve the appropriate secured simulator tool callable and arguments for an Action."""
        t_entity = action.target_entity
        params = dict(action.parameters)
        task_id = action.task_id

        # 1. Banking tools
        if action.action_type == ActionType.READ and t_entity.startswith("account:"):
            acc_id = params.get("account_id") or t_entity.removeprefix("account:")
            clean_kw = {k: v for k, v in params.items() if k not in ("account_id",)}
            def _tool_read_acc() -> Any:
                self.fault_injector.maybe_inject("read_account")
                return raw_read_account(self.state, task_id, acc_id, **clean_kw)
            return _tool_read_acc, (), {}

        if action.action_type == ActionType.READ and t_entity.startswith("invoice:"):
            inv_id = params.get("invoice_id") or t_entity
            clean_kw = {k: v for k, v in params.items() if k not in ("invoice_id",)}
            def _tool_read_inv() -> Any:
                self.fault_injector.maybe_inject("read_invoice")
                return raw_read_invoice(self.state, task_id, inv_id, **clean_kw)
            return _tool_read_inv, (), {}

        if action.action_type == ActionType.WRITE and (t_entity.startswith("vendor:") or "to_vendor_id" in params):
            from_acc = params.get("from_account_id", "acc-operating-001")
            vendor_id = params.get("to_vendor_id") or t_entity.removeprefix("vendor:")
            amt = float(params.get("amount", 0.0))
            inv_id = params.get("invoice_id")
            clean_kw = {
                k: v
                for k, v in params.items()
                if k not in ("from_account_id", "to_vendor_id", "amount", "invoice_id")
            }
            def _tool_prep_pay() -> Any:
                self.fault_injector.maybe_inject("prepare_payment")
                return raw_prepare_payment(self.state, task_id, from_acc, vendor_id, amt, inv_id, **clean_kw)
            return _tool_prep_pay, (), {}

        if action.action_type == ActionType.TRANSFER:
            from_acc = params.get("from_account_id", "acc-operating-001")
            vendor_id = params.get("to_vendor_id") or t_entity.removeprefix("vendor:")
            amt = float(params.get("amount", 0.0))
            app_id = params.get("approval_id")
            inv_id = params.get("invoice_id")
            clean_kw = {
                k: v
                for k, v in params.items()
                if k not in ("from_account_id", "to_vendor_id", "amount", "approval_id", "invoice_id")
            }
            def _tool_exec_pay() -> Any:
                self.fault_injector.maybe_inject("execute_payment")
                return raw_execute_payment(self.state, task_id, from_acc, vendor_id, amt, app_id, inv_id, **clean_kw)
            return _tool_exec_pay, (), {}

        # 2. Filesystem tools
        if action.action_type == ActionType.READ and (t_entity.startswith("file:") or "path" in params):
            path = params.get("path") or t_entity.removeprefix("file:")
            clean_kw = {k: v for k, v in params.items() if k not in ("path",)}
            def _tool_read_file() -> Any:
                self.fault_injector.maybe_inject("read_file")
                return raw_read_file(self.state, task_id, path, **clean_kw)
            return _tool_read_file, (), {}

        if action.action_type == ActionType.WRITE and (t_entity.startswith("file:") or "content" in params):
            path = params.get("path") or t_entity.removeprefix("file:")
            content = str(params.get("content", ""))
            clean_kw = {k: v for k, v in params.items() if k not in ("path", "content")}
            def _tool_write_file() -> Any:
                self.fault_injector.maybe_inject("write_file")
                return raw_write_file(self.state, task_id, path, content, **clean_kw)
            return _tool_write_file, (), {}

        if action.action_type == ActionType.DELETE and t_entity.startswith("file:"):
            path = params.get("path") or t_entity.removeprefix("file:")
            clean_kw = {k: v for k, v in params.items() if k not in ("path",)}
            def _tool_delete_file() -> Any:
                self.fault_injector.maybe_inject("delete_file")
                return raw_delete_file(self.state, task_id, path, **clean_kw)
            return _tool_delete_file, (), {}

        if action.action_type == ActionType.READ and (t_entity.startswith("dir:") or "directory" in params):
            directory = params.get("directory") or t_entity.removeprefix("dir:")
            clean_kw = {k: v for k, v in params.items() if k not in ("directory",)}
            def _tool_list_dir() -> Any:
                self.fault_injector.maybe_inject("list_dir")
                return raw_list_dir(self.state, task_id, directory, **clean_kw)
            return _tool_list_dir, (), {}

        # 3. HTTP Client tools
        if t_entity.startswith("http:") or t_entity.startswith("https:") or "url" in params:
            method = str(params.get("method", "GET"))
            url = str(params.get("url") or t_entity.removeprefix("http:"))
            payload = params.get("payload")
            clean_kw = {k: v for k, v in params.items() if k not in ("method", "url", "payload")}
            def _tool_http() -> Any:
                self.fault_injector.maybe_inject("http_request")
                return raw_http_request(self.state, task_id, method, url, payload, **clean_kw)
            return _tool_http, (), {}

        # 4. Database tools
        if t_entity.startswith("db:") or t_entity.startswith("table:") or "table" in params:
            tbl = str(params.get("table") or t_entity.removeprefix("db:").removeprefix("table:"))
            rec_id = str(params.get("record_id", ""))
            clean_kw = {k: v for k, v in params.items() if k not in ("table", "record_id", "data")}
            if action.action_type == ActionType.READ:
                def _tool_db_read() -> Any:
                    self.fault_injector.maybe_inject("db_read")
                    return raw_db_read(self.state, task_id, tbl, rec_id, **clean_kw)
                return _tool_db_read, (), {}
            if action.action_type == ActionType.WRITE:
                data = params.get("data", {})
                def _tool_db_write() -> Any:
                    self.fault_injector.maybe_inject("db_write")
                    return raw_db_write(self.state, task_id, tbl, rec_id, data, **clean_kw)
                return _tool_db_write, (), {}
            if action.action_type == ActionType.DELETE:
                def _tool_db_del() -> Any:
                    self.fault_injector.maybe_inject("db_delete")
                    return raw_db_delete(self.state, task_id, tbl, rec_id, **clean_kw)
                return _tool_db_del, (), {}

        # Default fallback simulator tool for abstract / custom entities
        def _fallback_tool() -> Dict[str, Any]:
            return {"status": "executed_in_simulation", "action_id": action.action_id}
        return _fallback_tool, (), {}

    def dispatch_action(self, action: Action) -> ExecutionResult:
        """Dispatch an action through ExecutionGateway using the resolved simulator tool."""
        tool_fn, args, kwargs = self.resolve_tool_for_action(action)
        return self.gateway.execute(action, tool_fn, *args, **kwargs)

