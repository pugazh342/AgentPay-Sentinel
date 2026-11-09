"""Execute every adversarial scenario and build a report from real results.

The runner creates one isolated application instance per scenario, drives the
attack through the public API (or the repository where the guard under test is
a database invariant), and derives ``test_status`` from the executed checks.

Nothing in this module invents results: a scenario is ``PASSED`` only when every
check produced by its executor is true and the observed decision, reason codes
and payment state match the declared expectation.
"""

from __future__ import annotations

import shutil
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from app.security_testing.models import (
    AdversarialReport,
    AttackScenario,
    ExecutionResult,
    ScenarioStatus,
)
from app.security_testing.reporting import build_report
from app.security_testing.invariants import INVARIANTS
from tests.adversarial.harness import ScenarioHarness
from tests.adversarial.scenarios import build_scenarios, get_executor

_EXPECTATION_CHECKS = (
    "expected_security_decision",
    "expected_reason_codes",
    "expected_payment_state",
)


def _expectation_checks(
    scenario: AttackScenario, result: ExecutionResult
) -> dict[str, bool]:
    return {
        "expected_security_decision": (
            result.actual_security_decision
            == scenario.expected_security_decision
        ),
        "expected_reason_codes": (
            tuple(result.actual_reason_codes)
            == tuple(scenario.expected_reason_codes)
        ),
        "expected_payment_state": (
            result.actual_payment_state == scenario.expected_payment_state
        ),
    }


def _execute_scenario(
    scenario: AttackScenario, directory: Path
) -> AttackScenario:
    executor = get_executor(scenario.executor)
    scenario_directory = directory / scenario.attack_id
    if scenario_directory.exists():
        # A reused --scratch-dir must not leak state into a new execution.
        shutil.rmtree(scenario_directory)
    try:
        with ScenarioHarness(scenario_directory) as harness:
            result = executor(harness)
    except BaseException as exc:  # noqa: BLE001 - reported as an ERROR scenario
        return scenario.with_result(
            {
                "security_decision": "ERROR",
                "reason_codes": [],
                "payment_state": None,
                "checks": {"executor_completed": False},
                "details": {
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                },
            },
            ScenarioStatus.ERROR,
        )

    checks = dict(result.checks)
    checks.update(_expectation_checks(scenario, result))
    status = (
        ScenarioStatus.PASSED
        if checks and all(bool(value) for value in checks.values())
        else ScenarioStatus.FAILED
    )
    return scenario.with_result(
        {
            "security_decision": result.actual_security_decision,
            "reason_codes": list(result.actual_reason_codes),
            "payment_state": result.actual_payment_state,
            "checks": checks,
            "details": dict(result.details),
        },
        status,
    )


def run_all_scenarios(
    directory: Path | str | None = None,
    scenarios: tuple[AttackScenario, ...] | None = None,
) -> AdversarialReport:
    """Execute all scenarios and return a report derived from their results.

    ``directory`` is an optional scratch directory. When omitted a temporary
    directory is created and removed automatically; scenario databases are
    never written into the repository.
    """

    registry = scenarios if scenarios is not None else build_scenarios()

    if directory is None:
        with TemporaryDirectory(prefix="agentpay-adversarial-") as temporary:
            executed = _run_registry(registry, Path(temporary))
    else:
        executed = _run_registry(registry, Path(directory))

    return build_report(executed, INVARIANTS)


def _run_registry(
    registry: tuple[AttackScenario, ...], directory: Path
) -> list[AttackScenario]:
    directory.mkdir(parents=True, exist_ok=True)
    return [
        _execute_scenario(scenario, directory)
        for scenario in sorted(registry, key=lambda item: item.attack_id)
    ]


def summarize(report: AdversarialReport) -> Mapping[str, Any]:
    """Return a compact, deterministic summary for CLI output."""

    return {
        "scenarios_total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "errors": report.errored,
        "skipped": report.skipped,
        "invariants_total": report.invariants_total,
        "invariants_verified": report.invariants_verified,
        "all_passed": report.all_passed,
    }


__all__ = ["run_all_scenarios", "summarize"]
