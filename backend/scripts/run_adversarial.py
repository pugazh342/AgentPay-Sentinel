"""Repeatable CLI runner for the AgentPay adversarial security simulation.

Usage (from ``backend/``)::

    python scripts/run_adversarial.py

Optional flags::

    --report-dir DIR     Directory for adversarial_report.json/.md
    --json PATH          Override the JSON report path
    --markdown PATH      Override the Markdown report path
    --scratch-dir DIR    Keep per-scenario SQLite databases in DIR

The runner never contacts PayPal or Gemini. Every attack is executed against
the real application services with deterministic provider doubles. A non-zero
exit code means at least one scenario or invariant failed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.security_testing.reporting import (  # noqa: E402
    assert_secret_free,
    render_json,
    render_markdown,
)
from tests.adversarial.runner import run_all_scenarios, summarize  # noqa: E402
from tests.conftest import TEST_HMAC_SECRET  # noqa: E402

_SECRET_ENV_VALUES = (
    "AGENTPAY_HMAC_SECRET",
    "HMAC_SECRET",
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "AGENTPAY_PAYPAL_CLIENT_ID",
    "AGENTPAY_PAYPAL_CLIENT_SECRET",
    "AGENTPAY_PAYPAL_WEBHOOK_ID",
    "GEMINI_API_KEY",
    "AGENTPAY_GEMINI_API_KEY",
)


def configured_secret_values() -> tuple[str, ...]:
    """Collect configured secret values for output scanning.

    Only used for substring detection. Values are never printed or written to
    a report; labels returned by the reporting module are positional.
    """

    values: list[str] = [TEST_HMAC_SECRET]
    env_file = BACKEND_ROOT / ".env"
    try:
        settings = Settings(
            _env_file=env_file if env_file.exists() else None
        )
    except Exception:  # noqa: BLE001 - scanning still works without settings
        settings = None

    if settings is not None:
        for value in (
            settings.hmac_secret_value,
            settings.paypal_client_id_value,
            settings.paypal_client_secret_value,
            settings.paypal_webhook_id_value,
            settings.gemini_api_key_value,
        ):
            if value:
                values.append(value)

    for name in _SECRET_ENV_VALUES:
        value = os.environ.get(name)
        if value:
            values.append(value)

    # Longest first so partial overlap cannot mask a longer secret.
    return tuple(sorted({value for value in values if value}, key=len, reverse=True))


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run deterministic adversarial payment-security scenarios and "
            "write machine-readable plus Markdown reports."
        )
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=BACKEND_ROOT / "reports",
        help="Directory for adversarial_report.json and .md (default: backend/reports).",
    )
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--markdown", type=Path, default=None)
    parser.add_argument("--scratch-dir", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    report = run_all_scenarios(directory=args.scratch_dir)

    json_path = args.json or (args.report_dir / "adversarial_report.json")
    markdown_path = args.markdown or (
        args.report_dir / "adversarial_report.md"
    )
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)

    json_text = render_json(report)
    markdown_text = render_markdown(report)

    # Fail closed before writing anything if configured secret material leaked
    # into a rendered report.
    secrets = configured_secret_values()
    assert_secret_free(json_text, secrets)
    assert_secret_free(markdown_text, secrets)

    json_path.write_text(json_text, encoding="utf-8", newline="\n")
    markdown_path.write_text(markdown_text, encoding="utf-8", newline="\n")

    print(json.dumps(summarize(report), sort_keys=True))
    print(f"json_report={json_path}")
    print(f"markdown_report={markdown_path}")

    return 0 if report.all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
