"""Deterministic JSON and Markdown rendering for adversarial reports.

Rendering is pure: the same executed scenarios always produce the same bytes.
No timestamps, hostnames, random identifiers or secrets are emitted.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from app.security_testing.models import (
    AdversarialReport,
    AttackScenario,
    Invariant,
    InvariantResult,
    ScenarioStatus,
)

REPORT_SCHEMA_VERSION = 1
REPORT_MILESTONE = "04"


def build_report(
    scenarios: Iterable[AttackScenario],
    invariants: Iterable[Invariant],
) -> AdversarialReport:
    """Order results deterministically and verify invariants from real statuses."""

    ordered_scenarios = tuple(sorted(scenarios, key=lambda item: item.attack_id))
    by_id = {scenario.attack_id: scenario for scenario in ordered_scenarios}

    invariant_results: list[InvariantResult] = []
    for invariant in sorted(invariants, key=lambda item: item.invariant_id):
        evidence: list[str] = []
        verified = True
        for scenario_id in invariant.scenario_ids:
            scenario = by_id.get(scenario_id)
            if scenario is None:
                verified = False
                evidence.append(f"{scenario_id}:MISSING")
                continue
            evidence.append(f"{scenario_id}:{scenario.test_status.value}")
            if scenario.test_status is not ScenarioStatus.PASSED:
                verified = False
        invariant_results.append(
            InvariantResult(
                invariant_id=invariant.invariant_id,
                description=invariant.description,
                scenario_ids=invariant.scenario_ids,
                verified=verified,
                evidence=tuple(evidence),
            )
        )

    return AdversarialReport(
        schema_version=REPORT_SCHEMA_VERSION,
        milestone=REPORT_MILESTONE,
        scenarios=ordered_scenarios,
        invariants=tuple(invariant_results),
    )


def _scenario_payload(scenario: AttackScenario) -> dict[str, Any]:
    return {
        "attack_id": scenario.attack_id,
        "category": scenario.category.value,
        "name": scenario.name,
        "description": scenario.description,
        "attack_input": dict(scenario.attack_input),
        "expected_security_decision": scenario.expected_security_decision,
        "expected_reason_codes": list(scenario.expected_reason_codes),
        "expected_payment_state": scenario.expected_payment_state,
        "actual_result": (
            dict(scenario.actual_result)
            if scenario.actual_result is not None
            else None
        ),
        "test_status": scenario.test_status.value,
    }


def report_payload(report: AdversarialReport) -> dict[str, Any]:
    """Convert a report into a plain JSON-serializable mapping."""

    return {
        "schema_version": report.schema_version,
        "milestone": report.milestone,
        "summary": {
            "scenarios_total": report.total,
            "passed": report.passed,
            "failed": report.failed,
            "errors": report.errored,
            "skipped": report.skipped,
            "invariants_total": report.invariants_total,
            "invariants_verified": report.invariants_verified,
            "all_passed": report.all_passed,
        },
        "scenarios": [_scenario_payload(item) for item in report.scenarios],
        "invariants": [
            {
                "invariant_id": item.invariant_id,
                "description": item.description,
                "scenario_ids": list(item.scenario_ids),
                "verified": item.verified,
                "evidence": list(item.evidence),
            }
            for item in report.invariants
        ],
    }


def render_json(report: AdversarialReport) -> str:
    """Render canonical, reproducible JSON (sorted keys, fixed indentation)."""

    return (
        json.dumps(
            report_payload(report),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    )


def _md(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text.replace("|", "\\|")


def _failing_checks(scenario: AttackScenario) -> tuple[str, ...]:
    actual = scenario.actual_result or {}
    checks = actual.get("checks") if isinstance(actual, dict) else None
    if not isinstance(checks, dict):
        return ()
    return tuple(sorted(name for name, passed in checks.items() if not passed))


def _actual_summary(scenario: AttackScenario) -> str:
    actual = scenario.actual_result or {}
    if scenario.test_status is ScenarioStatus.ERROR:
        details = actual.get("details") if isinstance(actual, dict) else {}
        error_type = details.get("error_type") if isinstance(details, dict) else None
        return f"ERROR ({error_type or 'unknown'})"
    decision = actual.get("security_decision")
    state = actual.get("payment_state")
    codes = actual.get("reason_codes") or []
    return f"{decision}; state={state}; reasons={','.join(str(code) for code in codes)}"


def render_markdown(report: AdversarialReport) -> str:
    """Render a concise human-readable summary of an executed report."""

    lines: list[str] = [
        "# AgentPay Sentinel - Adversarial Security Report",
        "",
        (
            "Milestone "
            f"{report.milestone}. Every result below was produced by executing the "
            "scenario against the application's real services with mocked external "
            "providers. No live PayPal payment or capture was performed."
        ),
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Scenarios executed | {report.total} |",
        f"| Passed | {report.passed} |",
        f"| Failed | {report.failed} |",
        f"| Errors | {report.errored} |",
        f"| Skipped | {report.skipped} |",
        f"| Invariants verified | {report.invariants_verified}/{report.invariants_total} |",
        f"| Overall | {'PASS' if report.all_passed else 'FAIL'} |",
        "",
        "## Security invariants",
        "",
        "| Invariant | Verified | Evidence |",
        "| --- | --- | --- |",
    ]

    for invariant in report.invariants:
        lines.append(
            "| {id} | {verified} | {evidence} |".format(
                id=_md(invariant.invariant_id),
                verified="yes" if invariant.verified else "NO",
                evidence=_md(", ".join(invariant.evidence)),
            )
        )

    lines.extend(
        [
            "",
            "## Scenarios",
            "",
            "| Attack ID | Category | Status | Expected decision | Expected state | Actual |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )

    for scenario in report.scenarios:
        lines.append(
            "| {id} | {category} | {status} | {decision} | {state} | {actual} |".format(
                id=_md(scenario.attack_id),
                category=_md(scenario.category.value),
                status=_md(scenario.test_status.value),
                decision=_md(scenario.expected_security_decision),
                state=_md(scenario.expected_payment_state),
                actual=_md(_actual_summary(scenario)),
            )
        )

    failures = [
        scenario
        for scenario in report.scenarios
        if scenario.test_status is not ScenarioStatus.PASSED
    ]
    if failures:
        lines.extend(["", "## Failed or errored scenarios", ""])
        for scenario in failures:
            failing = _failing_checks(scenario)
            lines.append(
                "- `{id}` ({status}): {name}{checks}".format(
                    id=scenario.attack_id,
                    status=scenario.test_status.value,
                    name=scenario.name,
                    checks=(
                        " - failing checks: " + ", ".join(failing)
                        if failing
                        else ""
                    ),
                )
            )
    else:
        lines.extend(
            [
                "",
                "## Failed or errored scenarios",
                "",
                "None. All executed scenarios met their expected security outcome.",
            ]
        )

    lines.append("")
    return "\n".join(lines) + "\n"


def find_secret_leaks(text: str, secrets: Sequence[str]) -> tuple[str, ...]:
    """Return stable labels for configured secrets found in rendered output.

    Labels are positional only; secret material is never returned or logged.
    """

    leaks: list[str] = []
    for index, secret in enumerate(secrets):
        if secret and secret in text:
            leaks.append(f"configured-secret-{index}")
    return tuple(leaks)


def redact_secrets(text: str, secrets: Sequence[str]) -> str:
    """Replace any configured secret value with a fixed redaction marker."""

    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def assert_secret_free(text: str, secrets: Sequence[str]) -> None:
    """Raise if rendered output contains a configured secret value."""

    leaks = find_secret_leaks(text, secrets)
    if leaks:
        raise ValueError(
            "refusing to write adversarial report containing secret material: "
            + ", ".join(leaks)
        )


__all__ = [
    "REPORT_MILESTONE",
    "REPORT_SCHEMA_VERSION",
    "assert_secret_free",
    "build_report",
    "find_secret_leaks",
    "redact_secrets",
    "render_json",
    "render_markdown",
    "report_payload",
]
