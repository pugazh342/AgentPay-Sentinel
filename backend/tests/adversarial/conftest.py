"""Session-scoped execution of the adversarial scenario suite.

Every deterministic scenario runs exactly once per test session. Individual
tests assert over the report produced by real execution instead of re-running
attacks, keeping the suite fast and the evidence consistent.
"""

from __future__ import annotations

import pytest

from app.security_testing.models import AdversarialReport
from tests.adversarial.runner import run_all_scenarios


@pytest.fixture(scope="session")
def adversarial_report(tmp_path_factory) -> AdversarialReport:
    directory = tmp_path_factory.mktemp("adversarial-execution")
    return run_all_scenarios(directory)
