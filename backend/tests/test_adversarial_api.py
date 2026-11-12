"""Tests for the adversarial API endpoints."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


class TestAdversarialReportEndpoint:
    """Tests for GET /api/adversarial/report endpoint."""

    def test_report_not_found_returns_404(self, client: TestClient, tmp_path: Path, monkeypatch) -> None:
        """Report endpoint returns 404 when no report exists (isolated path)."""
        import app.api.routes.adversarial as adv

        json_path = tmp_path / "adversarial_report.json"
        md_path = tmp_path / "adversarial_report.md"
        monkeypatch.setattr(adv, "_get_report_paths", lambda: (json_path, md_path))

        response = client.get("/api/adversarial/report")
        assert response.status_code == 404
        data = response.json()
        assert data["error"]["code"] == "NOT_FOUND"

    def test_report_returns_valid_json_structure(
        self, client: TestClient, tmp_path: Path, monkeypatch
    ) -> None:
        """Report endpoint returns properly structured JSON when report exists (isolated path)."""
        import app.api.routes.adversarial as adv
        from tests.adversarial.runner import run_all_scenarios
        from app.security_testing.reporting import render_json

        json_path = tmp_path / "adversarial_report.json"
        md_path = tmp_path / "adversarial_report.md"
        monkeypatch.setattr(adv, "_get_report_paths", lambda: (json_path, md_path))

        report = run_all_scenarios()
        json_text = render_json(report)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json_text, encoding="utf-8")

        response = client.get("/api/adversarial/report")
        assert response.status_code == 200

        data = response.json()
        assert "schema_version" in data
        assert "milestone" in data
        assert "scenarios" in data
        assert "invariants" in data
        assert "summary" in data


class TestAdversarialRunEndpoint:
    """Tests for POST /api/adversarial/run endpoint."""

    def test_run_succeeds_in_local_environment(
        self, client: TestClient, tmp_path: Path, monkeypatch
    ) -> None:
        """Run endpoint succeeds when explicitly enabled in local environment (isolated output)."""
        import app.api.routes.adversarial as adv

        monkeypatch.setenv("AGENTPAY_ENVIRONMENT", "local")
        monkeypatch.setenv("AGENTPAY_ADVERSARIAL_RUNNER_ENABLED", "true")
        json_path = tmp_path / "adversarial_report.json"
        md_path = tmp_path / "adversarial_report.md"
        monkeypatch.setattr(adv, "_get_report_paths", lambda: (json_path, md_path))

        response = client.post("/api/adversarial/run")

        assert response.status_code == 200
        data = response.json()
        assert "scenarios_total" in data
        assert "passed" in data
        assert "all_passed" in data
        assert json_path.exists() and md_path.exists()

    def test_run_forbidden_in_non_local_environment(
        self, client: TestClient, monkeypatch
    ) -> None:
        """Run endpoint returns 403 when not in local environment."""
        monkeypatch.setenv("AGENTPAY_ENVIRONMENT", "production")
        monkeypatch.setenv("AGENTPAY_ADVERSARIAL_RUNNER_ENABLED", "true")

        response = client.post("/api/adversarial/run")

        assert response.status_code == 403
        data = response.json()
        assert data["error"]["code"] in ("ADVERSARIAL_RUNNER_DISABLED", "FORBIDDEN")

    def test_run_disabled_by_default_when_not_explicitly_enabled(
        self, client: TestClient, monkeypatch
    ) -> None:
        """Runner is disabled by default outside explicit enablement."""
        monkeypatch.setenv("AGENTPAY_ENVIRONMENT", "local")
        monkeypatch.delenv("AGENTPAY_ADVERSARIAL_RUNNER_ENABLED", raising=False)

        response = client.post("/api/adversarial/run")

        assert response.status_code == 403
        data = response.json()
        assert data["error"]["code"] == "ADVERSARIAL_RUNNER_DISABLED"


class TestAdversarialReportSecurity:
    """Security tests for adversarial report generation."""

    def test_report_contains_no_secrets(self, client: TestClient, tmp_path: Path, monkeypatch) -> None:
        """Generated report contains no secret values (isolated output)."""
        import app.api.routes.adversarial as adv
        from tests.conftest import TEST_HMAC_SECRET

        monkeypatch.setenv("AGENTPAY_ENVIRONMENT", "local")
        monkeypatch.setenv("AGENTPAY_ADVERSARIAL_RUNNER_ENABLED", "true")
        json_path = tmp_path / "adversarial_report.json"
        md_path = tmp_path / "adversarial_report.md"
        monkeypatch.setattr(adv, "_get_report_paths", lambda: (json_path, md_path))

        # Run the adversarial suite
        response = client.post("/api/adversarial/run")

        if response.status_code == 200:
            # Get the report
            report_response = client.get("/api/adversarial/report")
            if report_response.status_code == 200:
                text = report_response.text
                # Verify test secret is not leaked
                assert TEST_HMAC_SECRET not in text

                # Verify environment secrets are redacted if present
                for secret_env in (
                    "AGENTPAY_HMAC_SECRET",
                    "PAYPAL_CLIENT_ID",
                    "PAYPAL_CLIENT_SECRET",
                    "GROQ_API_KEY",
                    "GEMINI_API_KEY",
                ):
                    secret = os.environ.get(secret_env)
                    if secret:
                        # Secrets should be redacted or not present
                        data = report_response.json()
                        text = json.dumps(data)
                        assert secret not in text, f"Secret from {secret_env} leaked in report"