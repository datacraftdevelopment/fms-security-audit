"""Credentials live only in the OS keychain (macOS Keychain, Windows Credential Manager)."""

import getpass
import json

SERVICE = "fms-security-audit"
KINDS = ("admin", "otto")


def _keyring():
    try:
        import keyring
    except ImportError as exc:  # pragma: no cover - environment problem
        raise SystemExit("The keyring package is missing. Run: pip install -r requirements.txt") from exc
    return keyring


def prompt_and_store(host, kind):
    label = {"admin": "FileMaker Admin Console", "otto": "OttoFMS"}[kind]
    user = input(f"{label} username for {host}: ").strip()
    password = getpass.getpass(f"{label} password (not shown): ")
    if not user or not password:
        raise SystemExit("Username and password are both required.")
    _keyring().set_password(SERVICE, f"{host}:{kind}", json.dumps({"user": user, "password": password}))


def get(host, kind):
    raw = _keyring().get_password(SERVICE, f"{host}:{kind}")
    if raw is None:
        return None
    data = json.loads(raw)
    return data["user"], data["password"]


def delete(host):
    removed = []
    keyring = _keyring()
    for kind in KINDS:
        try:
            keyring.delete_password(SERVICE, f"{host}:{kind}")
            removed.append(kind)
        except Exception:
            pass
    return removed
