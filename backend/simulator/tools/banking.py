"""Synthetic banking tool operations and action builders for AGENTGUARD simulator.

Provides simulated operations on accounts, invoices, and payment disbursement.
All tools are wrapped via ActionInterceptor to enforce deterministic gating:
  - Account/invoice reads require READ permission.
  - Payment preparation requires WRITE permission.
  - Payment execution requires TRANSFER permission, limit checks, and human approvals.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.security.models import Action, ActionType
from backend.simulator.models import InvoiceStatus, Payment, PaymentStatus
from backend.simulator.state import SimulationState


# ==============================================================================
# Action Builders
# ==============================================================================

def build_read_account_action(task_id: str, account_id: str, **kwargs: Any) -> Action:
    target = account_id if account_id.startswith("account:") else f"account:{account_id}"
    return Action(
        task_id=task_id,
        action_type=ActionType.READ,
        target_entity=target,
        parameters={"account_id": account_id, **kwargs},
    )


def build_read_invoice_action(task_id: str, invoice_id: str, **kwargs: Any) -> Action:
    target = invoice_id if invoice_id.startswith("invoice:") else f"invoice:{invoice_id}"
    return Action(
        task_id=task_id,
        action_type=ActionType.READ,
        target_entity=target,
        parameters={"invoice_id": invoice_id, **kwargs},
    )


def build_prepare_payment_action(
    task_id: str,
    from_account_id: str,
    to_vendor_id: str,
    amount: float,
    invoice_id: Optional[str] = None,
    **kwargs: Any,
) -> Action:
    target = to_vendor_id if to_vendor_id.startswith("vendor:") else f"vendor:{to_vendor_id}"
    return Action(
        task_id=task_id,
        action_type=ActionType.WRITE,
        target_entity=target,
        parameters={
            "from_account_id": from_account_id,
            "to_vendor_id": to_vendor_id,
            "amount": amount,
            "invoice_id": invoice_id,
            **kwargs,
        },
    )


def build_execute_payment_action(
    task_id: str,
    from_account_id: str,
    to_vendor_id: str,
    amount: float,
    approval_id: Optional[str] = None,
    invoice_id: Optional[str] = None,
    **kwargs: Any,
) -> Action:
    target = to_vendor_id if to_vendor_id.startswith("vendor:") else f"vendor:{to_vendor_id}"
    params: Dict[str, Any] = {
        "from_account_id": from_account_id,
        "to_vendor_id": to_vendor_id,
        "amount": amount,
        "invoice_id": invoice_id,
        **kwargs,
    }
    if approval_id is not None:
        params["approval_id"] = approval_id
    return Action(
        task_id=task_id,
        action_type=ActionType.TRANSFER,
        target_entity=target,
        parameters=params,
    )


# ==============================================================================
# Raw Simulation Implementations (operating on SimulationState)
# ==============================================================================

def raw_read_account(
    state: SimulationState, task_id: str, account_id: str, **kwargs: Any
) -> Dict[str, Any]:
    clean_acc_id = account_id.removeprefix("account:")
    acc = state.get_account(clean_acc_id) or state.get_account(account_id)
    if acc is None:
        raise KeyError(f"Account '{account_id}' not found.")
    return acc.model_dump()


def raw_read_invoice(
    state: SimulationState, task_id: str, invoice_id: str, **kwargs: Any
) -> Dict[str, Any]:
    clean_inv_id = invoice_id if invoice_id.startswith("invoice:") else f"invoice:{invoice_id}"
    inv = state.get_invoice(clean_inv_id) or state.get_invoice(invoice_id)
    if inv is None:
        raise KeyError(f"Invoice '{invoice_id}' not found.")
    return inv.model_dump()


def raw_prepare_payment(
    state: SimulationState,
    task_id: str,
    from_account_id: str,
    to_vendor_id: str,
    amount: float,
    invoice_id: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    if amount <= 0.0:
        raise ValueError(f"Payment amount must be positive, got {amount}.")

    acc = state.get_account(from_account_id)
    if acc is None:
        raise KeyError(f"Source account '{from_account_id}' does not exist.")
    if not acc.is_active:
        raise ValueError(f"Source account '{from_account_id}' is inactive.")

    clean_vendor_id = to_vendor_id.removeprefix("vendor:")
    vendor = state.get_vendor(clean_vendor_id)
    if vendor is None:
        raise KeyError(f"Destination vendor '{to_vendor_id}' does not exist.")

    # Validate invoice integrity if provided
    if invoice_id is not None:
        clean_inv_id = invoice_id if invoice_id.startswith("invoice:") else f"invoice:{invoice_id}"
        inv = state.get_invoice(clean_inv_id)
        if inv is None:
            raise KeyError(f"Invoice '{invoice_id}' does not exist.")
        if inv.status == InvoiceStatus.PAID:
            raise ValueError(f"Invoice '{invoice_id}' has already been paid.")
        if inv.status == InvoiceStatus.CANCELLED:
            raise ValueError(f"Invoice '{invoice_id}' is cancelled and cannot be paid.")
        if inv.vendor_id != clean_vendor_id:
            raise ValueError(
                f"Invoice vendor '{inv.vendor_id}' does not match payment destination '{clean_vendor_id}'."
            )
        if abs(inv.amount - amount) > 1e-4:
            raise ValueError(
                f"Payment amount {amount} does not match invoice amount {inv.amount}."
            )

    payment = Payment(
        payment_id=f"draft-{uuid.uuid4()}",
        from_account_id=from_account_id,
        to_vendor_id=clean_vendor_id,
        amount=amount,
        invoice_id=invoice_id,
        status=PaymentStatus.PREPARED,
    )
    state.record_payment(payment)
    return payment.model_dump()


def raw_execute_payment(
    state: SimulationState,
    task_id: str,
    from_account_id: str,
    to_vendor_id: str,
    amount: float,
    approval_id: Optional[str] = None,
    invoice_id: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute payment through thread-safe atomic settlement on SimulationState."""
    payment, remaining_balance = state.settle_invoice_payment(
        from_account_id=from_account_id,
        to_vendor_id=to_vendor_id,
        amount=amount,
        approval_id=approval_id,
        invoice_id=invoice_id,
    )
    return {
        "payment_id": payment.payment_id,
        "status": payment.status.value,
        "amount": payment.amount,
        "from_account_id": payment.from_account_id,
        "to_vendor_id": payment.to_vendor_id,
        "remaining_balance": remaining_balance,
        "settled_at": payment.executed_at.isoformat() if payment.executed_at else None,
    }

