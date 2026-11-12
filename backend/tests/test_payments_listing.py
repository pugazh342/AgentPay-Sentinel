"""Tests for payments listing API endpoint (Phase 3M.2).

These tests use isolated in-memory SQLite databases via shared conftest.py
fixtures and do not modify the production sandbox database.
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient


class TestPaymentsListing:
    """Tests for GET /api/v1/payments endpoint."""

    def test_empty_payment_list(self, payment_client: TestClient) -> None:
        """Test that listing returns empty array when no payments exist."""
        response = payment_client.get("/api/v1/payments")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0
        assert data["results"] == []

    def test_pagination_page_and_total_count(
        self,
        payment_client: TestClient,
        payment_intent_factory,
        payment_evaluate,
    ) -> None:
        """Test that total_count reflects filtered dataset size, not page size (Issue 1 fix verification)."""
        # Create intent and 10 payments
        for _ in range(10):
            intent = payment_intent_factory()
            transaction_resp = payment_evaluate(intent)
            assert transaction_resp.status_code == 200, transaction_resp.text
            transaction_id = transaction_resp.json()["transaction_id"]

            # Create payment via prepare endpoint
            response = payment_client.post(
                "/api/v1/payments",
                json={"transaction_id": transaction_id},
            )
            assert response.status_code == 200, response.text

        # Test with limit=1 should still return total_count=10
        response = payment_client.get("/api/v1/payments?limit=1")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 10, f"Expected total_count=10, got {data['total_count']}"
        # Results should be limited to 1
        assert len(data["results"]) == 1

        # Test with default limit should return all
        response = payment_client.get("/api/v1/payments")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 10
        assert len(data["results"]) == 10

    def test_pagination_offset_beyond_end_is_empty(self, payment_client: TestClient) -> None:
        """Test that offset beyond available results returns empty list."""
        response = payment_client.get("/api/v1/payments?limit=10&offset=1000")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0  # No payments exist
        assert data["results"] == []

    def test_state_filter(self, payment_client: TestClient) -> None:
        """Test filtering by payment state."""
        response = payment_client.get("/api/v1/payments?state=COMPLETED")
        assert response.status_code == 200
        data = response.json()
        # Should be valid even with no payments
        assert "total_count" in data
        assert "results" in data

    def test_state_filter_filters_correctly(
        self, payment_client: TestClient, payment_intent_factory, payment_evaluate
    ) -> None:
        """Test that state filter returns only matching payments."""
        # Create one payment (will be PENDING_USER_APPROVAL initially)
        intent = payment_intent_factory()
        transaction_resp = payment_evaluate(intent)
        assert transaction_resp.status_code == 200, transaction_resp.text
        transaction_id = transaction_resp.json()["transaction_id"]

        payment_client.post(
            "/api/v1/payments",
            json={"transaction_id": transaction_id},
        )

        # Query COMPLETED payments (should be 0)
        response = payment_client.get("/api/v1/payments?state=COMPLETED")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0
        assert len(data["results"]) == 0

    def test_intent_filter_valid(
        self, payment_client: TestClient, payment_intent_factory, payment_evaluate
    ) -> None:
        """Test filtering by valid intent_id."""
        from uuid import uuid4

        # Use a valid UUID - no payments should match
        response = payment_client.get(f"/api/v1/payments?intent_id={uuid4()}")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0

    def test_transaction_filter_valid(
        self, payment_client: TestClient, payment_intent_factory, payment_evaluate
    ) -> None:
        """Test filtering by valid transaction_id."""
        from uuid import uuid4

        # Use a valid UUID - no payments should match
        response = payment_client.get(f"/api/v1/payments?transaction_id={uuid4()}")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0

    def test_invalid_state_filter_is_422(self, payment_client: TestClient) -> None:
        """Test that invalid state filter is rejected with 422."""
        response = payment_client.get("/api/v1/payments?state=INVALID_STATE")
        assert response.status_code == 422

    def test_limit_above_maximum_is_rejected_with_422(self, payment_client: TestClient) -> None:
        """Test that limit above 1000 is rejected with 422 at schema validation."""
        response = payment_client.get("/api/v1/payments?limit=5000")
        assert response.status_code == 422, "limit > 1000 should be rejected with 422"

    def test_limit_zero_is_422(self, payment_client: TestClient) -> None:
        """Test that limit=0 is rejected with 422."""
        response = payment_client.get("/api/v1/payments?limit=0")
        assert response.status_code == 422

    def test_negative_offset_is_422(self, payment_client: TestClient) -> None:
        """Test that negative offset is rejected with 422."""
        response = payment_client.get("/api/v1/payments?offset=-1")
        assert response.status_code == 422

    def test_invalid_intent_uuid_is_422(self, payment_client: TestClient) -> None:
        """Test that invalid intent_id UUID returns 422, not 500 (Issue 2 fix verification)."""
        response = payment_client.get("/api/v1/payments?intent_id=not-a-uuid")
        assert response.status_code == 422, "Invalid UUID should return 422, not 500"
        # Verify it's actually a validation error
        assert "error" in response.json()

    def test_invalid_transaction_uuid_is_422(self, payment_client: TestClient) -> None:
        """Test that invalid transaction_id UUID returns 422, not 500 (Issue 2 fix verification)."""
        response = payment_client.get("/api/v1/payments?transaction_id=not-a-uuid")
        assert response.status_code == 422, "Invalid UUID should return 422, not 500"
        # Verify it's actually a validation error
        assert "error" in response.json()

    def test_listing_excludes_approval_url(self, payment_client: TestClient) -> None:
        """Verify approval_url is excluded from listing responses (security requirement)."""
        response = payment_client.get("/api/v1/payments")
        assert response.status_code == 200
        data = response.json()

        # Check that results don't contain approval_url
        for payment in data["results"]:
            assert "approval_url" not in payment, "approval_url should not be exposed in listing"
            assert "hmac_fingerprint" not in payment
            assert "user_id" not in payment
            assert "raw_response" not in payment

    def test_listing_does_not_mutate_database(
        self, payment_client: TestClient, settings
    ) -> None:
        """Verify that payment listing is read-only and doesn't modify the database."""
        # Compute row counts before
        def compute_row_counts(db_path: str) -> dict[str, int]:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            counts = {}
            tables = [
                "payments",
                "purchase_intents",
                "transaction_evaluations",
                "threat_analyses",
                "security_events",
                "paypal_webhook_events",
            ]
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    counts[table] = cursor.fetchone()[0]
                except Exception:
                    counts[table] = 0
            conn.close()
            return counts

        db_path = settings.database_url.replace("sqlite:///", "")
        counts_before = compute_row_counts(db_path)

        # Make listing requests
        response = payment_client.get("/api/v1/payments?limit=1000")
        assert response.status_code == 200

        counts_after = compute_row_counts(db_path)

        # Verify no mutations occurred
        for table, count_before in counts_before.items():
            assert counts_after[table] == count_before, f"{table} was mutated during listing request"

    def test_payment_detail_shows_approval_url(
        self, payment_client: TestClient, payment_intent_factory, payment_evaluate, stub_paypal
    ) -> None:
        """Verify approval_url IS present in payment detail (Issue 3 fix verification)."""
        from app.domain.payment import PayPalOrderResult
        from decimal import Decimal

        # Create a full payment flow to get approval_url
        intent = payment_intent_factory()
        transaction_resp = payment_evaluate(intent)
        transaction_id = transaction_resp.json()["transaction_id"]

        # Prepare payment
        response = payment_client.post(
            "/api/v1/payments",
            json={"transaction_id": transaction_id},
        )
        assert response.status_code == 200, response.text
        payment = response.json()
        payment_id = payment["payment_id"]

        # Approve to create PayPal order (with approval_url)
        approved_response = payment_client.post(
            f"/api/v1/payments/{payment_id}/approve",
            json={"approved_by": "test_operator"},
        )
        assert approved_response.status_code == 200, approved_response.text
        approved = approved_response.json()

        # Verify approval_url is present in detail response
        assert "approval_url" in approved, "approval_url should be present in payment detail"
        assert approved["approval_url"] is not None
        assert approved["approval_url"].startswith("https://www.sandbox.paypal.com/")