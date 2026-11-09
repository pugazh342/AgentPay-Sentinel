"""Adversarial security simulation framework.

This package contains only reporting/data models. Attack fixtures, harnesses
and executors live under ``tests/adversarial`` so production business logic is
never mixed with test-only attack definitions.
"""

from app.security_testing.models import (
    AdversarialReport,
    AttackCategory,
    AttackScenario,
    ExecutionResult,
    Invariant,
    InvariantResult,
    ScenarioStatus,
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
