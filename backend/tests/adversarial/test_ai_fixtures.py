"""Validity checks for the shared adversarial AI prompt fixtures."""

from __future__ import annotations

from tests.adversarial.ai_fixtures import (
    FIXTURES,
    REQUIRED_ATTACK_CLASSES,
    get_fixture,
)
from tests.adversarial.scenarios import build_scenarios
from tests.conftest import TEST_HMAC_SECRET

MAX_FIELD_CHARS = {
    "product_title": 200,
    "product_description": 2_000,
    "merchant_name": 200,
    "agent_reasoning": 2_000,
    "transaction_context": 1_000,
}


def test_every_required_attack_class_has_a_fixture() -> None:
    covered = {fixture.attack_class for fixture in FIXTURES}
    assert REQUIRED_ATTACK_CLASSES <= covered


def test_fixture_ids_and_text_are_unique_and_non_empty() -> None:
    ids = [fixture.fixture_id for fixture in FIXTURES]
    texts = [fixture.text for fixture in FIXTURES]
    assert len(ids) == len(set(ids))
    assert len(texts) == len(set(texts))
    for fixture in FIXTURES:
        assert fixture.fixture_id.strip()
        assert fixture.text.strip()
        assert fixture.attack_class.strip()


def test_fixtures_respect_provider_input_bounds() -> None:
    for fixture in FIXTURES:
        limit = MAX_FIELD_CHARS[fixture.injection_field]
        assert len(fixture.text) <= limit, fixture.fixture_id


def test_fixtures_contain_no_real_secret_material() -> None:
    for fixture in FIXTURES:
        assert TEST_HMAC_SECRET not in fixture.text
        lowered = fixture.text.lower()
        for marker in (
            "client_secret=",
            "access_token=",
            "bearer ",
            "sk_live_",
        ):
            assert marker not in lowered, fixture.fixture_id


def test_get_fixture_returns_declared_fixture_and_rejects_unknown() -> None:
    for fixture in FIXTURES:
        assert get_fixture(fixture.fixture_id) is fixture
    try:
        get_fixture("AI-FX-DOES-NOT-EXIST")
    except KeyError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("unknown fixture id must raise KeyError")


def test_ai_scenarios_reference_known_fixtures() -> None:
    known_ids = {fixture.fixture_id for fixture in FIXTURES}
    referenced = {
        scenario.attack_input["fixture_id"]
        for scenario in build_scenarios()
        if "fixture_id" in scenario.attack_input
    }
    assert referenced
    assert referenced <= known_ids
