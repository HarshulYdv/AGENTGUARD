"""Pydantic v2 data models for AGENTGUARD execution simulation.

Represents synthetic financial entities (accounts, vendors, invoices, payments)
and their operational statuses. All models are immutable (frozen=True) to ensure
clean, reproducible simulation snapshots.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class InvoiceStatus(str, Enum):
    """Lifecycle statuses for synthetic invoices."""

    PENDING = "pending"
    PAID = "paid"
    CANCELLED = "cancelled"


class PaymentStatus(str, Enum):
    """Lifecycle states for synthetic payments."""

    PREPARED = "prepared"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"
    REJECTED = "rejected"


class BankAccount(BaseModel):
    """Synthetic bank account."""

    model_config = ConfigDict(frozen=True)

    account_id: str = Field(
        description="Unique bank account identifier (e.g. 'acc-operating-001').",
    )
    owner: str = Field(
        description="Account holder or organization name.",
    )
    balance: float = Field(
        default=0.0,
        ge=0.0,
        description="Current ledger balance in the account.",
    )
    currency: str = Field(
        default="USD",
        description="Three-letter currency code.",
    )
    is_active: bool = Field(
        default=True,
        description="Whether the account is open for transactions.",
    )


class Vendor(BaseModel):
    """Synthetic vendor / supplier entity."""

    model_config = ConfigDict(frozen=True)

    vendor_id: str = Field(
        description="Unique vendor identifier (e.g. 'acme-corp').",
    )
    name: str = Field(
        description="Commercial or trade name of the vendor.",
    )
    bank_account_id: str = Field(
        description="Destination bank account ID for payments.",
    )
    is_sanctioned: bool = Field(
        default=False,
        description="Flag indicating if the vendor is on a sanctions list.",
    )
    country: str = Field(
        default="US",
        description="Two-letter ISO country code of incorporation.",
    )


class Invoice(BaseModel):
    """Synthetic commercial invoice."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str = Field(
        description="Unique invoice identifier (e.g. 'inv-acme-101').",
    )
    vendor_id: str = Field(
        description="Vendor who issued this invoice.",
    )
    amount: float = Field(
        gt=0.0,
        description="Monetary amount billed on the invoice.",
    )
    currency: str = Field(
        default="USD",
        description="Three-letter currency code.",
    )
    due_date: Optional[str] = Field(
        default=None,
        description="ISO date string for payment deadline.",
    )
    status: InvoiceStatus = Field(
        default=InvoiceStatus.PENDING,
        description="Current payment status of the invoice.",
    )
    description: str = Field(
        default="",
        description="Line-item description or memo.",
    )


class Payment(BaseModel):
    """Synthetic payment record."""

    model_config = ConfigDict(frozen=True)

    payment_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique payment transaction reference.",
    )
    invoice_id: Optional[str] = Field(
        default=None,
        description="Associated invoice ID, if linked to a bill.",
    )
    from_account_id: str = Field(
        description="Source bank account ID disbursing funds.",
    )
    to_vendor_id: str = Field(
        description="Beneficiary vendor ID receiving funds.",
    )
    amount: float = Field(
        gt=0.0,
        description="Disbursed monetary amount.",
    )
    currency: str = Field(
        default="USD",
        description="Three-letter currency code.",
    )
    status: PaymentStatus = Field(
        default=PaymentStatus.PREPARED,
        description="Lifecycle status of this payment attempt.",
    )
    approval_id: Optional[str] = Field(
        default=None,
        description="Authoritative approval ID that authorized this payment.",
    )
    executed_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when the payment settled in simulation.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Failure reason if the payment was rejected or failed.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary simulation metadata.",
    )

