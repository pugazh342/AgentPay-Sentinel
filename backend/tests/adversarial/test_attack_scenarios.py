"""Deterministic adversarial scenarios executed against real application code."""

from __future__ import annotations

import pytest

from app.security_testing.models import AdversarialReport, ScenarioStatus
from tests.adversarial.scenarios import build_scenarios

SCENARIOS = build_scenarios()
SCENARIO_IDS = [scenario.attack_id for scenario in SCENARIOS]


@pytest.mark.parametrize(
    "attack_id",
    SCENARIO_IDS,
    ids=SCENARIO_IDS,
)
def test_attack_scenario_meets_expected_security_outcome(
    adversarial_report: AdversarialReport, attack_id: str
) -> None:
    scenario = next(
        item
        for item in adversarial_report.scenarios
        if item.attack_id == attack_id
    )
    assert scenario.test_status is ScenarioStatus.PASSED, {
        "attack_id": scenario.attack_id,
        "test_status": scenario.test_status.value,
        "expected_decision": scenario.expected_security_decision,
        "expected_reason_codes": scenario.expected_reason_codes,
        "expected_payment_state": scenario.expected_payment_state,
        "actual_result": scenario.actual_result,
    }


def test_report_contains_every_registered_scenario(
    adversarial_report: AdversarialReport,
) -> None:
    executed_ids = {
        scenario.attack_id for scenario in adversarial_report.scenarios
    }
    assert executed_ids == set(SCENARIO_IDS)
    assert adversarial_report.total == len(SCENARIOS)


def test_no_scenario_is_left_unexecuted(
    adversarial_report: AdversarialReport,
) -> None:
    pending = [
        scenario.attack_id
        for scenario in adversarial_report.scenarios
        if scenario.test_status is ScenarioStatus.PENDING
    ]
    assert pending == []


def test_no_scenario_error_or_failure(
    adversarial_report: AdversarialReport,
) -> None:
    bad = [
        (scenario.attack_id, scenario.test_status.value)
        for scenario in adversarial_report.scenarios
        if scenario.test_status
        not in {ScenarioStatus.PASSED, ScenarioStatus.SKIPPED}
    ]
    assert bad == []


def test_attack_ids_are_unique_and_stable() -> None:
    assert len(SCENARIO_IDS) == len(set(SCENARIO_IDS))
    assert SCENARIO_IDS == sorted(SCENARIO_IDS)


def test_registry_declares_expected_payment_states() -> None:
    valid_states = {
        "PENDING_SECURITY",
        "REVIEW_REQUIRED",
        "BLOCKED",
        "PENDING_USER_APPROVAL",
        "PAYPAL_ORDER_CREATED",
        "BUYER_APPROVED",
        "CAPTURE_PENDING",
        "COMPLETED",
        "FAILED",
        "EXPIRED",
        None,
    }
    for scenario in SCENARIOS:
        assert scenario.expected_payment_state in valid_states
        assert scenario.expected_security_decision in {
            "ALLOW_FOR_APPROVAL",
            "REVIEW_REQUIRED",
            "BLOCK",
            "NOT_APPLICABLE",
        }
        assert scenario.description.strip()
        assert scenario.attack_input
