"""Unit tests for deterministic report models and rendering."""

from __future__ import annotations

import json

import pytest

from app.security_testing.models import (
    AttackCategory,
    AttackScenario,
    Invariant,
    ScenarioStatus,
)
from app.security_testing.reporting import (
    assert_secret_free,
    build_report,
    find_secret_leaks,
    redact_secrets,
    render_json,
    render_markdown,
    report_payload,
)


def _scenario(
    attack_id: str,
    *,
    status: ScenarioStatus = ScenarioStatus.PASSED,
    checks: dict[str, bool] | None = None,
    decision: str = "BLOCK",
    state: str | None = "BLOCKED",
) -> AttackScenario:
    return AttackScenario(
        attack_id=attack_id,
        category=AttackCategory.POLICY,
        name=f"Scenario {attack_id}",
        description="Synthetic scenario used to test rendering.",
        attack_input={"amount": "900.00"},
        expected_security_decision=decision,
        expected_reason_codes=("AMOUNT_EXCEEDS_MAXIMUM",),
        expected_payment_state=state,
        executor="policy_amount",
        actual_result={
            "security_decision": decision,
            "reason_codes": ["AMOUNT_EXCEEDS_MAXIMUM"],
            "payment_state": state,
            "checks": checks or {"observed": True},
            "details": {},
        },
        test_status=status,
    )


def _invariant(
    invariant_id: str, scenario_ids: tuple[str, ...]
) -> Invariant:
    return Invariant(
        invariant_id=invariant_id,
        description="Synthetic invariant.",
        scenario_ids=scenario_ids,
    )


def test_json_rendering_is_byte_identical_across_calls() -> None:
    report = build_report([_scenario("A-001"), _scenario("B-001")], [])
    assert render_json(report) == render_json(report)


def test_report_orders_scenarios_and_invariants_deterministically() -> None:
    first = build_report(
        [_scenario("B-001"), _scenario("A-001")],
        [_invariant("INV-B", ("A-001",)), _invariant("INV-A", ("A-001",))],
    )
    second = build_report(
        [_scenario("A-001"), _scenario("B-001")],
        [_invariant("INV-A", ("A-001",)), _invariant("INV-B", ("A-001",))],
    )
    assert render_json(first) == render_json(second)
    assert [item.attack_id for item in first.scenarios] == ["A-001", "B-001"]
    assert [item.invariant_id for item in first.invariants] == [
        "INV-A",
        "INV-B",
    ]


def test_json_report_has_no_wall_clock_or_random_fields() -> None:
    report = build_report([_scenario("A-001")], [])
    payload = json.loads(render_json(report))
    serialized = json.dumps(payload, sort_keys=True)
    for forbidden in (
        "timestamp",
        "generated_at",
        "created_at",
        "run_id",
        "hostname",
        "duration",
    ):
        assert forbidden not in serialized
    assert payload["schema_version"] == 1
    assert payload["summary"]["scenarios_total"] == 1
    assert payload["summary"]["all_passed"] is True


def test_invariants_are_verified_only_from_passed_scenarios() -> None:
    report = build_report(
        [
            _scenario("A-001", status=ScenarioStatus.PASSED),
            _scenario("B-001", status=ScenarioStatus.FAILED),
        ],
        [_invariant("INV-OK", ("A-001",)), _invariant("INV-BAD", ("B-001",))],
    )
    by_id = {item.invariant_id: item for item in report.invariants}
    assert by_id["INV-OK"].verified is True
    assert by_id["INV-BAD"].verified is False
    assert by_id["INV-BAD"].evidence == ("B-001:FAILED",)


def test_missing_invariant_scenario_is_not_verified() -> None:
    report = build_report([_scenario("A-001")], [_invariant("INV-X", ("Z-999",))])
    invariant = report.invariants[0]
    assert invariant.verified is False
    assert invariant.evidence == ("Z-999:MISSING",)


def test_markdown_reports_failures_clearly() -> None:
    failing = _scenario(
        "A-001",
        status=ScenarioStatus.FAILED,
        checks={"expected_security_decision": False, "observed": True},
    )
    report = build_report([failing], [_invariant("INV-A", ("A-001",))])
    markdown = render_markdown(report)
    assert "| Overall | FAIL |" in markdown
    assert "## Failed or errored scenarios" in markdown
    assert "failing checks: expected_security_decision" in markdown
    assert "A-001" in markdown


def test_markdown_reports_success_without_failure_section_entries() -> None:
    report = build_report([_scenario("A-001")], [_invariant("INV-A", ("A-001",))])
    markdown = render_markdown(report)
    assert "| Overall | PASS |" in markdown
    assert "All executed scenarios met their expected security outcome." in markdown


def test_counts_reflect_actual_statuses() -> None:
    report = build_report(
        [
            _scenario("A-001", status=ScenarioStatus.PASSED),
            _scenario("B-001", status=ScenarioStatus.FAILED),
            _scenario("C-001", status=ScenarioStatus.ERROR),
            _scenario("D-001", status=ScenarioStatus.SKIPPED),
        ],
        [],
    )
    assert report.total == 4
    assert report.passed == 1
    assert report.failed == 1
    assert report.errored == 1
    assert report.skipped == 1
    assert report.all_passed is False


def test_secret_scanning_detects_and_redacts_configured_values() -> None:
    secret = "do-not-leak-this-value"
    text = f"report body contains {secret} inside"
    assert find_secret_leaks(text, (secret,)) == ("configured-secret-0",)
    assert secret not in redact_secrets(text, (secret,))
    with pytest.raises(ValueError):
        assert_secret_free(text, (secret,))
    assert_secret_free("clean report", (secret,))


def test_report_payload_contains_required_attack_fields() -> None:
    payload = report_payload(build_report([_scenario("A-001")], []))
    scenario = payload["scenarios"][0]
    for field in (
        "attack_id",
        "category",
        "name",
        "description",
        "attack_input",
        "expected_security_decision",
        "expected_reason_codes",
        "expected_payment_state",
        "actual_result",
        "test_status",
    ):
        assert field in scenario, field


def test_with_result_does_not_mutate_original_scenario() -> None:
    original = _scenario("A-001", status=ScenarioStatus.PENDING)
    updated = original.with_result(
        {"security_decision": "BLOCK"}, ScenarioStatus.PASSED
    )
    assert original.test_status is ScenarioStatus.PENDING
    assert updated.test_status is ScenarioStatus.PASSED
