"""Tests for synthetic banking tools and approval workflows in AGENTGUARD simulator (Stage 04)."""

from __future__ import annotations

import concurrent.futures
import threading

import pytest

from backend.security.models import (
    ActionType,
    ApprovalRequirement,
    TaskContext,
    Verdict,
)
from backend.simulator.models import InvoiceStatus, PaymentStatus
from backend.simulator.sandbox import SimulationSandbox
from backend.simulator.tools.banking import (
    raw_execute_payment,
    raw_prepare_payment,
)


@pytest.fixture
def sandbox() -> SimulationSandbox:
    return SimulationSandbox()


@pytest.fixture
def finance_task(sandbox: SimulationSandbox) -> TaskContext:
    task = TaskContext(
        task_id="task-sim-banking-01",
        original_instruction="Disburse ACME vendor invoices up to $10,000.",
        allowed_actions=[ActionType.READ, ActionType.WRITE, ActionType.TRANSFER],
        denied_actions=[ActionType.DELETE],
        allowed_entities=[
            "account:acc-operating-001",
            "invoice:acme-101",
            "invoice:acme-102",
            "vendor:acme-corp",
        ],
        restricted_entities=["vendor:sanctioned-offshore"],
        transaction_limits={"transfer": 10000.0},
        approval_requirements=[
            ApprovalRequirement(
                action_types=[ActionType.TRANSFER],
                min_amount=5000.0,
                approver_roles=["supervisor", "finance_director"],
            )
        ],
    )
    return sandbox.context_manager.create_task(task)


def test_authorized_account_and_invoice_read(
    sandbox: SimulationSandbox, finance_task: TaskContext
) -> None:
    """Agent can read authorized account and invoice."""
    # 1. Read Account
    res_acc = sandbox.read_account(finance_task.task_id, "acc-operating-001")
    assert res_acc.executed is True
    assert res_acc.decision.decision == Verdict.ALLOW
    assert res_acc.result["account_id"] == "acc-operating-001"
    assert res_acc.result["balance"] == 50000.0

    # 2. Read Invoice
    res_inv = sandbox.read_invoice(finance_task.task_id, "invoice:acme-101")
    assert res_inv.executed is True
    assert res_inv.decision.decision == Verdict.ALLOW
    assert res_inv.result["invoice_id"] == "invoice:acme-101"
    assert res_inv.result["amount"] == 2500.0


def test_unauthorized_vendor_payment_blocked(
    sandbox: SimulationSandbox, finance_task: TaskContext
) -> None:
    """Payment to a restricted/sanctioned vendor is blocked and never touches state."""
    # Prerequisite read
    sandbox.read_account(finance_task.task_id, "acc-operating-001")

    initial_balance = sandbox.state.get_account("acc-operating-001").balance

    # Attempt payment to sanctioned vendor
    res = sandbox.execute_payment(
        finance_task.task_id,
        from_account_id="acc-operating-001",
        to_vendor_id="vendor:sanctioned-offshore",
        amount=1000.0,
    )

    assert res.executed is False
    assert res.decision.decision == Verdict.BLOCK
    # Balance must be completely untouched
    assert sandbox.state.get_account("acc-operating-001").balance == initial_balance


def test_payment_over_limit_blocked(
    sandbox: SimulationSandbox, finance_task: TaskContext
) -> None:
    """Payment exceeding transaction limit ($15,000 > $10,000) is blocked."""
    sandbox.read_account(finance_task.task_id, "acc-operating-001")
    initial_balance = sandbox.state.get_account("acc-operating-001").balance

    res = sandbox.execute_payment(
        finance_task.task_id,
        from_account_id="acc-operating-001",
        to_vendor_id="vendor:acme-corp",
        amount=15000.0,
    )

    assert res.executed is False
    assert res.decision.decision == Verdict.BLOCK
    assert "exceeds the limit of 10000.0" in res.error
    assert sandbox.state.get_account("acc-operating-001").balance == initial_balance


def test_payment_requiring_approval_workflow(
    sandbox: SimulationSandbox, finance_task: TaskContext
) -> None:
    """Full end-to-end human-in-the-loop approval workflow:
    1. Agent proposes $7,500 transfer without approval -> REQUIRE_APPROVAL (paused)
    2. Supervisor grants approval via ApprovalService
    3. Agent re-proposes transfer with valid approval_id -> ALLOW (executed)
    4. Account balance is settled, invoice is marked PAID
    """
    sandbox.read_account(finance_task.task_id, "acc-operating-001")
    initial_balance = sandbox.state.get_account("acc-operating-001").balance

    # Step 1: Attempt $7,500 payment (threshold is $5,000)
    res_step1 = sandbox.execute_payment(
        finance_task.task_id,
        from_account_id="acc-operating-001",
        to_vendor_id="vendor:acme-corp",
        amount=7500.0,
        invoice_id="invoice:acme-102",
    )
    assert res_step1.executed is False
    assert res_step1.decision.decision == Verdict.REQUIRE_APPROVAL
    assert sandbox.state.get_account("acc-operating-001").balance == initial_balance
    assert sandbox.state.get_invoice("invoice:acme-102").status == InvoiceStatus.PENDING

    # Step 2: Human supervisor grants approval out-of-band
    approval = sandbox.approvals.grant_approval(
        task_id=finance_task.task_id,
        action_type=ActionType.TRANSFER,
        target_entity="vendor:acme-corp",
        approved_by="supervisor_alice",
        approver_role="supervisor",
        max_amount=8000.0,
    )
    assert approval.approval_id is not None

    # Step 3: Agent executes payment referencing valid approval_id
    res_step3 = sandbox.execute_payment(
        finance_task.task_id,
        from_account_id="acc-operating-001",
        to_vendor_id="vendor:acme-corp",
        amount=7500.0,
        approval_id=approval.approval_id,
        invoice_id="invoice:acme-102",
    )
    assert res_step3.executed is True
    assert res_step3.success is True
    assert res_step3.decision.decision == Verdict.ALLOW
    assert res_step3.result["status"] == PaymentStatus.EXECUTED.value

    # Step 4: Verify ledger and invoice status
    new_balance = sandbox.state.get_account("acc-operating-001").balance
    assert new_balance == initial_balance - 7500.0
    assert sandbox.state.get_invoice("invoice:acme-102").status == InvoiceStatus.PAID


# ==============================================================================
# Remediation Regression Tests (SEC-04-003 & SEC-04-004)
# ==============================================================================

def test_concurrent_payment_execution_atomicity(sandbox: SimulationSandbox) -> None:
    """SEC-04-003: Concurrent payment debits must be atomic under state lock.

    Account balance is $10,000. 5 threads simultaneously attempt a $3,000 debit.
    Exactly 3 threads must succeed ($9,000 debited) and 2 must fail due to insufficient funds.
    Final balance must be exactly $1,000 without race condition overdrafts.
    """
    account_id = "acc-operating-001"
    sandbox.state.update_balance(account_id, 10000.0)

    success_count = 0
    failure_count = 0
    lock = threading.Lock()

    def _worker() -> None:
        nonlocal success_count, failure_count
        try:
            raw_execute_payment(
                state=sandbox.state,
                task_id="task-concurrency-test",
                from_account_id=account_id,
                to_vendor_id="acme-corp",
                amount=3000.0,
            )
            with lock:
                success_count += 1
        except ValueError as exc:
            if "Insufficient funds" in str(exc):
                with lock:
                    failure_count += 1
            else:
                raise

    threads = [threading.Thread(target=_worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert success_count == 3
    assert failure_count == 2
    final_balance = sandbox.state.get_account(account_id).balance
    assert final_balance == 1000.0


def test_payment_execution_prevents_duplicate_invoice_payment(
    sandbox: SimulationSandbox,
) -> None:
    """SEC-04-004: Paying an already-paid invoice must be rejected atomically."""
    # First payment succeeds
    res1 = raw_execute_payment(
        state=sandbox.state,
        task_id="task-duplicate-pay",
        from_account_id="acc-operating-001",
        to_vendor_id="acme-corp",
        amount=2500.0,
        invoice_id="invoice:acme-101",
    )
    assert res1["status"] == PaymentStatus.EXECUTED.value
    assert sandbox.state.get_invoice("invoice:acme-101").status == InvoiceStatus.PAID

    # Duplicate payment attempt on the same invoice must be rejected
    with pytest.raises(ValueError, match="already been paid"):
        raw_execute_payment(
            state=sandbox.state,
            task_id="task-duplicate-pay",
            from_account_id="acc-operating-001",
            to_vendor_id="acme-corp",
            amount=2500.0,
            invoice_id="invoice:acme-101",
        )


def test_payment_execution_rejects_cancelled_invoice(
    sandbox: SimulationSandbox,
) -> None:
    """SEC-04-004: Paying a cancelled invoice must be rejected."""
    sandbox.state.update_invoice_status("invoice:acme-101", InvoiceStatus.CANCELLED)

    with pytest.raises(ValueError, match="cancelled and cannot be paid"):
        raw_execute_payment(
            state=sandbox.state,
            task_id="task-cancelled-pay",
            from_account_id="acc-operating-001",
            to_vendor_id="acme-corp",
            amount=2500.0,
            invoice_id="invoice:acme-101",
        )


def test_payment_execution_rejects_vendor_mismatch(
    sandbox: SimulationSandbox,
) -> None:
    """SEC-04-004: Payment destination must match the invoice's vendor."""
    with pytest.raises(ValueError, match="does not match payment destination"):
        raw_execute_payment(
            state=sandbox.state,
            task_id="task-vendor-mismatch",
            from_account_id="acc-operating-001",
            to_vendor_id="globex-inc",  # invoice:acme-101 belongs to acme-corp
            amount=2500.0,
            invoice_id="invoice:acme-101",
        )


def test_payment_execution_rejects_amount_mismatch(
    sandbox: SimulationSandbox,
) -> None:
    """SEC-04-004: Payment amount must match invoice amount."""
    with pytest.raises(ValueError, match="does not match invoice amount"):
        raw_execute_payment(
            state=sandbox.state,
            task_id="task-amount-mismatch",
            from_account_id="acc-operating-001",
            to_vendor_id="acme-corp",
            amount=3000.0,  # invoice:acme-101 is $2,500.0
            invoice_id="invoice:acme-101",
        )


def test_prepare_payment_validates_invoice_integrity(
    sandbox: SimulationSandbox,
) -> None:
    """SEC-04-004: Preparation step must also enforce invoice integrity checks."""
    # Paid invoice check
    sandbox.state.update_invoice_status("invoice:acme-101", InvoiceStatus.PAID)
    with pytest.raises(ValueError, match="already been paid"):
        raw_prepare_payment(
            state=sandbox.state,
            task_id="task-prep-check",
            from_account_id="acc-operating-001",
            to_vendor_id="acme-corp",
            amount=2500.0,
            invoice_id="invoice:acme-101",
        )

