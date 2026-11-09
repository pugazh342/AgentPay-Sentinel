"""Durable conditional-transition tests for the payment repository.

These tests exercise the database guard directly, without HTTP or PayPal. They
prove that concurrent capture claims cannot both succeed and that a transaction
can own at most one payment row.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from threading import Barrier, Thread
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import IntegrityError

from app.domain.enums import PaymentState
from app.domain.payment import Payment
from app.persistence.database import Database
from app.persistence.orm import TransactionRow
from app.persistence.repositories import SqlAlchemyPaymentRepository

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _seed(tmp_path, *, state: PaymentState = PaymentState.BUYER_APPROVED):
    database = Database(f"sqlite:///{(tmp_path / 'concurrency.db').as_posix()}")
    database.create_all()

    transaction_id = uuid4()
    intent_id = uuid4()
    payment_id = uuid4()

    with database.session() as session:
        session.add(
            TransactionRow(
                transaction_id=str(transaction_id),
                request_id="req_concurrency",
                user_id="user_1",
                intent_id=str(intent_id),
                merchant_id="merchant_1",
                product_category="footwear",
                amount="800.00",
                currency="USD",
                quantity=1,
                decision_id=str(uuid4()),
                decision="ALLOW_FOR_APPROVAL",
                reason_codes=["ALL_CHECKS_PASSED"],
                explanation="All hard authorization checks passed.",
                risk_level="LOW",
                evaluated_at=NOW,
            )
        )
        # The transaction row must exist before the payment row because the
        # payments.transaction_id foreign key is enforced by SQLite.
        session.flush()
        repository = SqlAlchemyPaymentRepository(session)
        repository.add(
            Payment(
                payment_id=payment_id,
                transaction_id=transaction_id,
                intent_id=intent_id,
                user_id="user_1",
                merchant_id="merchant_1",
                product_category="footwear",
                amount=Decimal("800.00"),
                currency="USD",
                state=state,
                version=0,
                created_at=NOW,
                updated_at=NOW,
                paypal_order_id="PAYPAL-ORDER-CONCURRENCY",
            )
        )
        session.commit()

    return database, transaction_id, payment_id


def test_two_concurrent_capture_claims_only_one_succeeds(tmp_path) -> None:
    database, _transaction_id, payment_id = _seed(tmp_path)
    barrier = Barrier(2)
    results: list[bool] = []
    errors: list[BaseException] = []

    def claim() -> None:
        try:
            with database.session() as session:
                repository = SqlAlchemyPaymentRepository(session)
                payment = repository.get(payment_id)
                assert payment is not None
                version = payment.version
                # Release the read transaction so both threads race on the
                # conditional UPDATE rather than on SQLite's read lock.
                session.commit()

                barrier.wait(timeout=10)
                claimed = repository.transition(
                    payment_id,
                    expected_states=frozenset({PaymentState.BUYER_APPROVED}),
                    new_state=PaymentState.CAPTURE_PENDING,
                    expected_version=version,
                    updated_at=NOW,
                )
                session.commit()
                results.append(claimed is not None)
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [Thread(target=claim), Thread(target=claim)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert errors == []
    assert sorted(results) == [False, True]

    with database.session() as session:
        payment = SqlAlchemyPaymentRepository(session).get(payment_id)
        assert payment is not None
        assert payment.state is PaymentState.CAPTURE_PENDING
        assert payment.version == 1


def test_second_payment_row_for_same_transaction_is_rejected(tmp_path) -> None:
    database, transaction_id, _payment_id = _seed(tmp_path)

    duplicate = Payment(
        payment_id=uuid4(),
        transaction_id=UUID(str(transaction_id)),
        intent_id=uuid4(),
        user_id="user_1",
        merchant_id="merchant_1",
        product_category="footwear",
        amount=Decimal("800.00"),
        currency="USD",
        state=PaymentState.PENDING_USER_APPROVAL,
        version=0,
        created_at=NOW,
        updated_at=NOW,
    )

    with pytest.raises(IntegrityError):
        with database.session() as session:
            SqlAlchemyPaymentRepository(session).add(duplicate)
            session.flush()
