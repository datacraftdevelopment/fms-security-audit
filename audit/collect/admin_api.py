"""Collect FileMaker Server settings through the Admin API (v2), read-only.

Endpoint paths and response field names vary between FileMaker Server versions and
have not all been verified against every release. Every endpoint is optional: a
missing one is recorded, and the rules that need it report Not checked.
"""

import datetime as dt
import json
from pathlib import Path

from audit import secrets
from audit.collect import tls
from audit.http import ReadOnlySession

BASE = "/fmi/admin/api/v2"

# name -> candidate paths, tried in order
ENDPOINTS = {
    "metadata": ["/server/metadata"],
    "general": ["/server/config/general"],
    "security": ["/server/config/security"],
    "databases": ["/databases"],
    "clients": ["/clients"],
    "schedules": ["/schedules"],
    "dataapi": ["/fmdapi/config"],
    "odata": ["/fmodata/config", "/odata/config"],
    "webdirect": ["/webdirect/config"],
    "xml": ["/xml/config"],
    "php": ["/php/config"],
    "plugins": ["/plugins", "/server/config/plugins"],
}


def login(session, url, host):
    creds = secrets.get(host, "admin")
    if creds is None:
        raise SystemExit(f"No stored credentials for {host}. Run: python -m audit login {host}")
    resp = session.post(f"{url}{BASE}/user/auth", auth=creds, json={})
    if resp.status_code != 200:
        raise SystemExit(f"Admin API login failed ({resp.status_code}). Check the credentials and that the Admin Console is reachable.")
    token = resp.json().get("response", {}).get("token")
    if not token:
        raise SystemExit("Admin API login returned no token.")
    session.headers["Authorization"] = f"Bearer {token}"
    return token


def logout(session, url, token):
    try:
        session.delete(f"{url}{BASE}/user/auth/{token}")
    except Exception:
        pass


def fetch_all(session, url):
    raw = {}
    for name, paths in ENDPOINTS.items():
        entry = {"ok": False}
        for path in paths:
            try:
                resp = session.get(f"{url}{BASE}{path}")
            except Exception as exc:
                entry = {"ok": False, "error": str(exc)}
                continue
            if resp.status_code == 200:
                try:
                    body = resp.json()
                except ValueError:
                    entry = {"ok": False, "path": path, "status": 200, "error": "not a JSON response"}
                    continue
                entry = {"ok": True, "path": path, "data": body.get("response", body) if isinstance(body, dict) else body}
                break
            entry = {"ok": False, "path": path, "status": resp.status_code}
        raw[name] = entry
    return raw


def check_connection(host, allow_untrusted=False):
    url = f"https://{host}"
    session = ReadOnlySession()
    session.verify = not allow_untrusted
    token = login(session, url, host)
    logout(session, url, token)


def collect(host, out_dir, allow_untrusted=False):
    out = Path(out_dir)
    url = f"https://{host}"
    cert = tls.certificate(host)
    if cert["trusted"] is False and not allow_untrusted:
        raise SystemExit(
            f"The server's certificate is not trusted ({cert['error']}). This is itself a finding. "
            "If the client agrees to continue, re-run with --allow-untrusted-cert."
        )
    session = ReadOnlySession()
    session.verify = not allow_untrusted
    token = login(session, url, host)
    try:
        raw = fetch_all(session, url)
    finally:
        logout(session, url, token)
    raw["certificate"] = {"ok": True, "data": cert}
    (out / "server_raw.json").write_text(json.dumps(raw, indent=2))
    server = normalize(raw, host)
    (out / "server.json").write_text(json.dumps(server, indent=2))
    return server


def _get(d, *keys):
    """First present key among alternatives, case-insensitive."""
    if not isinstance(d, dict):
        return None
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in lower:
            return lower[k.lower()]
    return None


def _list(d, *keys):
    if isinstance(d, list):
        return d
    value = _get(d, *keys)
    if isinstance(value, dict):
        return _list(value, *keys)
    return value if isinstance(value, list) else None


def _enabled(entry):
    if not entry.get("ok"):
        return None
    value = _get(entry["data"], "enabled", "enable", "status")
    if isinstance(value, str):
        return value.upper() in ("ENABLED", "ON", "TRUE", "RUNNING")
    return None if value is None else bool(value)


def normalize(raw, host):
    data = lambda name: raw.get(name, {}).get("data") if raw.get(name, {}).get("ok") else None  # noqa: E731

    files = None
    dbs = _list(data("databases"), "databases", "files")
    if dbs is not None:
        files = [
            {
                "name": _get(f, "filename", "name"),
                "encrypted": _get(f, "isEncrypted", "encrypted"),
                "ext_privs": _get(f, "enabledExtPrivileges", "extPrivileges") or [],
            }
            for f in dbs
        ]

    schedules = None
    sched = _list(data("schedules"), "schedules")
    if sched is not None:
        schedules = []
        for s in sched:
            script = _get(s, "filemakerScriptType", "scriptType", "script", "systemScriptType", "scriptSequenceType") or {}
            schedules.append(
                {
                    "name": _get(s, "name"),
                    "type": _get(s, "taskType", "type"),
                    "enabled": _get(s, "enabled", "status"),
                    "account": _get(script, "fmScriptAccount", "scriptAccount", "account", "accountName") if isinstance(script, dict) else None,
                    "last_result": _get(s, "lastError", "lastRunStatus", "lastResult", "status"),
                    "last_run": _get(s, "lastRun", "lastRunTime"),
                }
            )

    clients = None
    cl = _list(data("clients"), "clients")
    if cl is not None:
        clients = [
            {"account": _get(c, "userName", "accountName"), "machine": _get(c, "computerName", "hostName", "ipaddress")}
            for c in cl
        ]

    security = data("security")
    plugins = _list(data("plugins"), "plugins")
    return {
        "host": host,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "version": _get(data("metadata") or {}, "ServerVersion", "version"),
        "require_secure_db": _get(security or {}, "requireSecureDB") if security else None,
        "files": files,
        "webtech": {
            "dataapi": _enabled(raw.get("dataapi", {})),
            "odata": _enabled(raw.get("odata", {})),
            "webdirect": _enabled(raw.get("webdirect", {})),
            "xml": _enabled(raw.get("xml", {})),
            "php": _enabled(raw.get("php", {})),
        },
        "schedules": schedules,
        "clients": clients,
        "plugins": [(_get(p, "name", "filename") if isinstance(p, dict) else p) for p in plugins] if plugins is not None else None,
        "certificate": raw.get("certificate", {}).get("data"),
    }
