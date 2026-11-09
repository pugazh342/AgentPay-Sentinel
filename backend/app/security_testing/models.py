"""Data models for the adversarial security simulation.

A scenario describes an attack, the outcome the deterministic system *should*
produce, and (after execution) the outcome it *did* produce. ``test_status`` is
never authored by hand: it is derived from executed checks by the runner.

Reports deliberately contain no wall-clock timestamps and no random identifiers
so repeated runs of the same code produce byte-identical output.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Mapping


class AttackCategory(StrEnum):
    """Closed set of adversarial test categories."""

    POLICY = "POLICY"
    AUTHORIZATION = "AUTHORIZATION"
    INTEGRITY = "INTEGRITY"
    REPLAY = "REPLAY"
    AI = "AI"
    PAYMENT = "PAYMENT"
    WEBHOOK = "WEBHOOK"
    CONCURRENCY = "CONCURRENCY"
    STATE_MACHINE = "STATE_MACHINE"
    LIVE_ENDPOINT = "LIVE_ENDPOINT"


class ScenarioStatus(StrEnum):
    """Execution status derived from actual checks."""

    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Outcome produced by executing one attack through application services."""

    actual_security_decision: str
    actual_reason_codes: tuple[str, ...]
    actual_payment_state: str | None
    checks: Mapping[str, bool] = field(default_factory=dict)
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackScenario:
    """A deterministic, reproducible adversarial scenario.

    ``actual_result`` and ``test_status`` are populated only by the runner after
    the scenario has been executed against the real application.
    """

    attack_id: str
    category: AttackCategory
    name: str
    description: str
    attack_input: Mapping[str, Any]
    expected_security_decision: str
    expected_reason_codes: tuple[str, ...]
    expected_payment_state: str | None
    executor: str
    actual_result: Mapping[str, Any] | None = None
    test_status: ScenarioStatus = ScenarioStatus.PENDING

    def with_result(
        self,
        actual_result: Mapping[str, Any],
        test_status: ScenarioStatus,
    ) -> AttackScenario:
        return replace(
            self,
            actual_result=actual_result,
            test_status=test_status,
        )


@dataclass(frozen=True, slots=True)
class Invariant:
    """A security guarantee that must hold across a set of scenarios."""

    invariant_id: str
    description: str
    scenario_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class InvariantResult:
    """Verification result derived from executed scenario statuses."""

    invariant_id: str
    description: str
    scenario_ids: tuple[str, ...]
    verified: bool
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdversarialReport:
    """Complete report over executed scenarios and verified invariants."""

    schema_version: int
    milestone: str
    scenarios: tuple[AttackScenario, ...]
    invariants: tuple[InvariantResult, ...]

    @property
    def total(self) -> int:
        return len(self.scenarios)

    def count(self, status: ScenarioStatus) -> int:
        return sum(1 for scenario in self.scenarios if scenario.test_status is status)

    @property
    def passed(self) -> int:
        return self.count(ScenarioStatus.PASSED)

    @property
    def failed(self) -> int:
        return self.count(ScenarioStatus.FAILED)

    @property
    def errored(self) -> int:
        return self.count(ScenarioStatus.ERROR)

    @property
    def skipped(self) -> int:
        return self.count(ScenarioStatus.SKIPPED)

    @property
    def invariants_total(self) -> int:
        return len(self.invariants)

    @property
    def invariants_verified(self) -> int:
        return sum(1 for invariant in self.invariants if invariant.verified)

    @property
    def all_passed(self) -> bool:
        return (
            self.total > 0
            and self.passed == self.total
            and self.invariants_verified == self.invariants_total
        )


__all__ = [
    "AdversarialReport",
    "AttackCategory",
    "AttackScenario",
    "ExecutionResult",
    "Invariant",
    "InvariantResult",
    "ScenarioStatus",
]
