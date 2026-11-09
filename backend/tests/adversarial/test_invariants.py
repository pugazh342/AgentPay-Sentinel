"""Invariant verification derived from executed adversarial scenarios.

Invariants are not asserted from prose. Each one is verified only when every
scenario it references actually passed in this run.
"""

from __future__ import annotations

import pytest

from app.security_testing.invariants import INVARIANTS
from app.security_testing.models import AdversarialReport, ScenarioStatus

REQUIRED_INVARIANTS = {
    "INV-01-AI-CANNOT-OVERRIDE-BLOCK",
    "INV-02-AI-CANNOT-DOWNGRADE-REVIEW",
    "INV-03-AI-CANNOT-AUTHORIZE",
    "INV-04-EXPIRED-OR-MODIFIED-INTENT-NO-CAPTURE",
    "INV-05-WEBHOOK-REQUIRES-SIGNATURE",
    "INV-06-NO-DUPLICATE-CAPTURE",
    "INV-07-AI-FAILURE-NO-AUTHORIZATION",
    "INV-08-BROWSER-RETURN-NO-SUCCESS",
    "INV-09-NO-LIVE-PAYPAL",
    "INV-10-DETERMINISTIC-AUTHORITY",
    "INV-11-ONE-PAYMENT-PER-TRANSACTION",
    "INV-12-PROVIDER-BINDING",
    "INV-13-CAPTURE-REQUIRES-CLAIM",
    "INV-14-STATE-MACHINE-CLOSED",
}


def test_every_required_invariant_is_declared() -> None:
    declared = {invariant.invariant_id for invariant in INVARIANTS}
    assert REQUIRED_INVARIANTS <= declared


def test_invariants_reference_registered_scenarios(
    adversarial_report: AdversarialReport,
) -> None:
    executed = {
        scenario.attack_id for scenario in adversarial_report.scenarios
    }
    for invariant in INVARIANTS:
        assert invariant.scenario_ids, invariant.invariant_id
        missing = set(invariant.scenario_ids) - executed
        assert not missing, (invariant.invariant_id, sorted(missing))


def test_all_invariants_verified_by_real_execution(
    adversarial_report: AdversarialReport,
) -> None:
    failed = [
        {
            "invariant_id": invariant.invariant_id,
            "evidence": invariant.evidence,
        }
        for invariant in adversarial_report.invariants
        if not invariant.verified
    ]
    assert failed == []
    assert adversarial_report.invariants_verified == (
        adversarial_report.invariants_total
    )


@pytest.mark.parametrize(
    "invariant_id",
    sorted(REQUIRED_INVARIANTS),
)
def test_named_invariant_is_verified(
    adversarial_report: AdversarialReport, invariant_id: str
) -> None:
    invariant = next(
        item
        for item in adversarial_report.invariants
        if item.invariant_id == invariant_id
    )
    assert invariant.verified is True, invariant.evidence
    for scenario_id in invariant.scenario_ids:
        scenario = next(
            item
            for item in adversarial_report.scenarios
            if item.attack_id == scenario_id
        )
        assert scenario.test_status is ScenarioStatus.PASSED
