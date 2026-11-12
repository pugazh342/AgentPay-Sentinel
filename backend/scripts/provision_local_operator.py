#!/usr/bin/env python3
"""Secure local operator credential provisioning for AgentPay Sentinel.

Run interactively in a local terminal (PowerShell/CMD/bash). This utility:
- Prompts for operator username and password via hidden input (getpass).
- Generates a PBKDF2-SHA256 password hash using the backend's auth implementation.
- Generates a cryptographically secure session signing secret.
- Updates the backend .env atomically while preserving all unrelated settings.
- Never prints passwords, hashes, secrets, cookies, or tokens.

Do NOT pass credentials as command-line arguments.
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure backend package is importable when run from repo root or backend dir.
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.security.auth import hash_password, verify_password  # noqa: E402

AUTH_KEYS = {
    "AGENTPAY_AUTH_ENABLED": "true",
    "AGENTPAY_OPERATOR_USERNAME": None,
    "AGENTPAY_OPERATOR_PASSWORD_HASH": None,
    "AGENTPAY_OPERATOR_SESSION_SECRET": None,
    "AGENTPAY_OPERATOR_SESSION_TTL_SECONDS": "3600",
    "AGENTPAY_OPERATOR_COOKIE_SECURE": "false",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision local operator authentication credentials (interactive)."
    )
    parser.add_argument(
        "--env-file",
        default=str(BACKEND_DIR / ".env"),
        help="Path to backend .env file to update (default: backend/.env)",
    )
    parser.add_argument(
        "--ttl-seconds",
        type=int,
        default=3600,
        help="Operator session TTL in seconds (default: 3600)",
    )
    parser.add_argument(
        "--secure-cookies",
        action="store_true",
        help="Set AGENTPAY_OPERATOR_COOKIE_SECURE=true (required for HTTPS). Default is false for local HTTP localhost testing.",
    )
    return parser.parse_args()


def read_env_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def upsert_env(lines: list[str], updates: dict[str, str]) -> list[str]:
    remaining = dict(updates)
    out: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            out.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in remaining:
            out.append(f"{key}={remaining.pop(key)}\n")
        else:
            out.append(line if line.endswith("\n") else line + "\n")
    if remaining:
        if out and not out[-1].endswith("\n"):
            out[-1] = out[-1] + "\n"
        if out:
            out.append("\n# --- Operator authentication (provisioned locally) ---\n")
        for key, value in remaining.items():
            out.append(f"{key}={value}\n")
    return out


def has_existing_operator_config(lines: list[str]) -> bool:
    keys = {"AGENTPAY_OPERATOR_USERNAME", "AGENTPAY_OPERATOR_PASSWORD_HASH", "AGENTPAY_OPERATOR_SESSION_SECRET"}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() in keys and value.strip():
            return True
    return False


def set_restrictive_permissions(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    if os.name == "nt":
        try:
            username = os.environ.get("USERNAME")
            if username:
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception:
            pass


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        set_restrictive_permissions(Path(tmp_name))
        os.replace(tmp_name, path)
        set_restrictive_permissions(path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except Exception:
            pass
        raise


def prompt_credentials() -> tuple[str, str]:
    username = input("Operator username: ").strip()
    if not username:
        raise ValueError("Username must not be empty.")

    password = getpass.getpass("Operator password (hidden): ")
    if not password:
        raise ValueError("Password must not be empty.")
    confirm = getpass.getpass("Confirm password (hidden): ")
    if password != confirm:
        raise ValueError("Passwords do not match.")

    return username, password


def main() -> int:
    args = parse_args()
    env_path = Path(args.env_file).resolve()

    if args.ttl_seconds < 300 or args.ttl_seconds > 86400:
        print("ERROR: --ttl-seconds must be between 300 and 86400.", file=sys.stderr)
        return 2

    try:
        existing_lines = read_env_lines(env_path)
        if has_existing_operator_config(existing_lines):
            answer = input(
                "Existing operator credentials detected in env file. Overwrite? Type 'YES' to continue: "
            ).strip()
            if answer != "YES":
                print("Aborted. No changes written.")
                return 1

        username, password = prompt_credentials()

        password_hash = hash_password(password)
        # Sanity check using the same verifier before writing.
        if not verify_password(password, password_hash):
            raise RuntimeError("Generated password hash failed local verification.")

        session_secret = secrets.token_urlsafe(48)
        if len(session_secret.encode("utf-8")) < 32:
            raise RuntimeError("Generated session secret does not meet length requirements.")

        updates = {
            "AGENTPAY_AUTH_ENABLED": "true",
            "AGENTPAY_OPERATOR_USERNAME": username,
            "AGENTPAY_OPERATOR_PASSWORD_HASH": password_hash,
            "AGENTPAY_OPERATOR_SESSION_SECRET": session_secret,
            "AGENTPAY_OPERATOR_SESSION_TTL_SECONDS": str(args.ttl_seconds),
            "AGENTPAY_OPERATOR_COOKIE_SECURE": "true" if args.secure_cookies else "false",
        }

        new_lines = upsert_env(existing_lines, updates)
        content = "".join(new_lines)
        atomic_write(env_path, content)

        print("Operator authentication configuration updated successfully.")
        print(f"Updated file: {env_path}")
        print("No passwords, hashes, secrets, cookies, or tokens were printed.")
        print("Next: restart backend/frontend with preserved existing HMAC/PayPal settings and verify auth.")
        return 0
    except KeyboardInterrupt:
        print("\nAborted by user. No partial credential file should remain.")
        return 130
    except Exception as exc:
        # Avoid leaking secrets; exceptions here should not contain credential material.
        print(f"ERROR: {exc}", file=sys.stderr)
        print("No partial credential file should remain.")
        return 1
    finally:
        # Best-effort cleanup of sensitive locals.
        try:
            password  # type: ignore[name-defined]
            del password
        except Exception:
            pass
        try:
            password_hash  # type: ignore[name-defined]
            del password_hash
        except Exception:
            pass
        try:
            session_secret  # type: ignore[name-defined]
            del session_secret
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
