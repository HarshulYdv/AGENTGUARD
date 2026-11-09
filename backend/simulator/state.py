"""SimulationState — Thread-safe, isolated state container for the execution sandbox.

Holds synthetic entities (accounts, vendors, invoices, payments, virtual files,
mock database tables, mock HTTP routes). Can be reset or cloned to guarantee
test isolation and deterministic replay.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.simulator.models import (
    BankAccount,
    Invoice,
    InvoiceStatus,
    Payment,
    PaymentStatus,
    Vendor,
)


class SimulationState:
    """Thread-safe in-memory state container for the AGENTGUARD simulator."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._accounts: Dict[str, BankAccount] = {}
        self._vendors: Dict[str, Vendor] = {}
        self._invoices: Dict[str, Invoice] = {}
        self._payments: Dict[str, Payment] = {}
        self._virtual_files: Dict[str, bytes] = {}
        self._mock_tables: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._mock_http_routes: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._seed_factory: Optional[Callable[[SimulationState], None]] = None

    # ------------------------------------------------------------------
    # Bank Accounts API
    # ------------------------------------------------------------------

    def add_account(self, account: BankAccount) -> BankAccount:
        with self._lock:
            self._accounts[account.account_id] = account
            return account

    def get_account(self, account_id: str) -> Optional[BankAccount]:
        with self._lock:
            return self._accounts.get(account_id)

    def list_accounts(self) -> List[BankAccount]:
        with self._lock:
            return list(self._accounts.values())

    def update_balance(self, account_id: str, new_balance: float) -> BankAccount:
        with self._lock:
            acc = self._accounts.get(account_id)
            if acc is None:
                raise KeyError(f"Account '{account_id}' does not exist.")
            if new_balance < 0.0:
                raise ValueError("Account balance cannot be negative.")
            updated = BankAccount(
                account_id=acc.account_id,
                owner=acc.owner,
                balance=new_balance,
                currency=acc.currency,
                is_active=acc.is_active,
            )
            self._accounts[account_id] = updated
            return updated

    def debit_account(self, account_id: str, amount: float) -> Tuple[BankAccount, float]:
        """Atomically verify balance and debit the specified account under state lock."""
        if amount <= 0.0:
            raise ValueError(f"Debit amount must be positive, got {amount}.")
        with self._lock:
            acc = self._accounts.get(account_id)
            if acc is None:
                raise KeyError(f"Account '{account_id}' does not exist.")
            if not acc.is_active:
                raise ValueError(f"Account '{account_id}' is inactive.")
            if acc.balance < amount:
                raise ValueError(
                    f"Insufficient funds: account '{account_id}' has balance {acc.balance}, requires {amount}."
                )
            new_balance = round(acc.balance - amount, 4)
            updated = BankAccount(
                account_id=acc.account_id,
                owner=acc.owner,
                balance=new_balance,
                currency=acc.currency,
                is_active=acc.is_active,
            )
            self._accounts[account_id] = updated
            return updated, new_balance

    # ------------------------------------------------------------------
    # Vendors API
    # ------------------------------------------------------------------

    def add_vendor(self, vendor: Vendor) -> Vendor:
        with self._lock:
            self._vendors[vendor.vendor_id] = vendor
            return vendor

    def get_vendor(self, vendor_id: str) -> Optional[Vendor]:
        with self._lock:
            return self._vendors.get(vendor_id)

    def list_vendors(self) -> List[Vendor]:
        with self._lock:
            return list(self._vendors.values())

    # ------------------------------------------------------------------
    # Invoices API
    # ------------------------------------------------------------------

    def add_invoice(self, invoice: Invoice) -> Invoice:
        with self._lock:
            self._invoices[invoice.invoice_id] = invoice
            return invoice

    def get_invoice(self, invoice_id: str) -> Optional[Invoice]:
        with self._lock:
            return self._invoices.get(invoice_id)

    def list_invoices(self, status: Optional[InvoiceStatus] = None) -> List[Invoice]:
        with self._lock:
            if status is None:
                return list(self._invoices.values())
            return [inv for inv in self._invoices.values() if inv.status == status]

    def update_invoice_status(
        self, invoice_id: str, new_status: InvoiceStatus
    ) -> Invoice:
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if inv is None:
                raise KeyError(f"Invoice '{invoice_id}' does not exist.")
            updated = Invoice(
                invoice_id=inv.invoice_id,
                vendor_id=inv.vendor_id,
                amount=inv.amount,
                currency=inv.currency,
                due_date=inv.due_date,
                status=new_status,
                description=inv.description,
            )
            self._invoices[invoice_id] = updated
            return updated

    # ------------------------------------------------------------------
    # Payments API
    # ------------------------------------------------------------------

    def record_payment(self, payment: Payment) -> Payment:
        with self._lock:
            self._payments[payment.payment_id] = payment
            return payment

    def get_payment(self, payment_id: str) -> Optional[Payment]:
        with self._lock:
            return self._payments.get(payment_id)

    def list_payments(self) -> List[Payment]:
        with self._lock:
            return list(self._payments.values())

    def settle_invoice_payment(
        self,
        from_account_id: str,
        to_vendor_id: str,
        amount: float,
        approval_id: Optional[str] = None,
        invoice_id: Optional[str] = None,
    ) -> Tuple[Payment, float]:
        """Atomically validate account, vendor, and invoice integrity, debit balance, and record payment under state lock."""
        if amount <= 0.0:
            raise ValueError(f"Payment amount must be positive, got {amount}.")

        with self._lock:
            # 1. Validate account
            acc = self._accounts.get(from_account_id)
            if acc is None:
                raise KeyError(f"Source account '{from_account_id}' does not exist.")
            if not acc.is_active:
                raise ValueError(f"Source account '{from_account_id}' is inactive.")
            if acc.balance < amount:
                raise ValueError(
                    f"Insufficient funds: account '{from_account_id}' has balance {acc.balance}, requires {amount}."
                )

            # 2. Validate vendor
            clean_vendor_id = to_vendor_id.removeprefix("vendor:")
            vendor = self._vendors.get(clean_vendor_id)
            if vendor is None:
                raise KeyError(f"Destination vendor '{to_vendor_id}' does not exist.")

            # 3. Validate invoice integrity if provided
            clean_inv_id = None
            if invoice_id is not None:
                clean_inv_id = invoice_id if invoice_id.startswith("invoice:") else f"invoice:{invoice_id}"
                inv = self._invoices.get(clean_inv_id)
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

            # 4. Atomic balance deduction
            new_balance = round(acc.balance - amount, 4)
            updated_acc = BankAccount(
                account_id=acc.account_id,
                owner=acc.owner,
                balance=new_balance,
                currency=acc.currency,
                is_active=acc.is_active,
            )
            self._accounts[from_account_id] = updated_acc

            # 5. Atomic invoice status transition
            if clean_inv_id is not None:
                inv = self._invoices[clean_inv_id]
                updated_inv = Invoice(
                    invoice_id=inv.invoice_id,
                    vendor_id=inv.vendor_id,
                    amount=inv.amount,
                    currency=inv.currency,
                    due_date=inv.due_date,
                    status=InvoiceStatus.PAID,
                    description=inv.description,
                )
                self._invoices[clean_inv_id] = updated_inv

            # 6. Record executed payment
            payment = Payment(
                payment_id=f"tx-{uuid.uuid4()}",
                from_account_id=from_account_id,
                to_vendor_id=clean_vendor_id,
                amount=amount,
                invoice_id=invoice_id,
                status=PaymentStatus.EXECUTED,
                approval_id=approval_id,
                executed_at=datetime.now(timezone.utc),
            )
            self._payments[payment.payment_id] = payment

            return payment, new_balance

    # ------------------------------------------------------------------
    # Virtual Filesystem State
    # ------------------------------------------------------------------

    def get_file(self, path: str) -> Optional[bytes]:
        with self._lock:
            return self._virtual_files.get(path)

    def set_file(self, path: str, content: bytes) -> None:
        with self._lock:
            self._virtual_files[path] = content

    def delete_file(self, path: str) -> bool:
        with self._lock:
            return self._virtual_files.pop(path, None) is not None

    def list_files(self, prefix: str = "") -> List[str]:
        with self._lock:
            if not prefix:
                return list(self._virtual_files.keys())
            return [p for p in self._virtual_files.keys() if p.startswith(prefix)]

    # ------------------------------------------------------------------
    # Mock Database Tables State
    # ------------------------------------------------------------------

    def get_table_record(
        self, table: str, record_id: str
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._mock_tables.get(table, {}).get(record_id)

    def set_table_record(
        self, table: str, record_id: str, data: Dict[str, Any]
    ) -> None:
        with self._lock:
            if table not in self._mock_tables:
                self._mock_tables[table] = {}
            self._mock_tables[table][record_id] = dict(data)

    def delete_table_record(self, table: str, record_id: str) -> bool:
        with self._lock:
            tbl = self._mock_tables.get(table)
            if tbl and record_id in tbl:
                del tbl[record_id]
                return True
            return False

    def list_table_records(self, table: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._mock_tables.get(table, {}).values())

    # ------------------------------------------------------------------
    # Mock HTTP Service State
    # ------------------------------------------------------------------

    def register_http_route(
        self, method: str, url: str, response_payload: Dict[str, Any]
    ) -> None:
        with self._lock:
            self._mock_http_routes[(method.upper(), url)] = response_payload

    def get_http_response(
        self, method: str, url: str
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._mock_http_routes.get((method.upper(), url))

    # ------------------------------------------------------------------
    # Lifecycle & Cleanup
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Clear all stored state collections to completely empty."""
        with self._lock:
            self._accounts.clear()
            self._vendors.clear()
            self._invoices.clear()
            self._payments.clear()
            self._virtual_files.clear()
            self._mock_tables.clear()
            self._mock_http_routes.clear()

    def reset(self) -> None:
        """Reset state: re-seed default fixtures if seed factory is attached, otherwise clear."""
        with self._lock:
            if self._seed_factory is not None:
                self._seed_factory(self)
            else:
                self.clear()

