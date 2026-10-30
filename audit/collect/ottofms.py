"""Collect OttoFMS settings through its Developer API (/otto/api), read-only.

OttoFMS shares the Admin Console identity, so the audit uses the OttoFMS
credentials if they were stored with `login --otto`, otherwise the Admin Console
ones. Auth is Basic on every request; there is no login or logout call.

Two things learned from live servers (OttoFMS 4.18, FileMaker Server 26):
- /otto/ is a web app with a catch-all, so an unknown path returns HTML with a
  200 status. Only a JSON response counts as an answer.
- /otto/api/info answers without credentials.

API key secrets are never written to disk: only the fields listed in KEY_FIELDS
are kept.
"""

import datetime as dt
import json
from pathlib import Path

from audit import secrets
from audit.http import ReadOnlySession

ENDPOINTS = {
    "info": "/otto/api/info",
    "api_keys": "/otto/api/api-key",
    "settings": "/otto/api/settings",
}

KEY_FIELDS = ("label", "database", "createdAt", "lastUsed", "expiration")


def _fetch(session, url, path):
    try:
        resp = session.get(f"{url}{path}")
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if "json" not in resp.headers.get("Content-Type", ""):
        return {"ok": False, "status": resp.status_code, "error": "not an API response (path missing on this OttoFMS version)"}
    if resp.status_code != 200:
        return {"ok": False, "status": resp.status_code}
    body = resp.json()
    return {"ok": True, "data": body.get("response", body) if isinstance(body, dict) else body}


def _keys(entry):
    if not entry.get("ok"):
        return None
    data = entry["data"]
    keys = data.get("api-keys", data.get("apiKeys", data)) if isinstance(data, dict) else data
    if not isinstance(keys, list):
        return None
    return [{f: k.get(f) for f in KEY_FIELDS} for k in keys if isinstance(k, dict)]


def normalize(raw, host):
    info = raw["info"].get("data") if raw["info"].get("ok") else None
    otto = (info or {}).get("Otto", {})
    fms = (info or {}).get("FileMakerServer", {})
    return {
        "host": host,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "installed": info is not None,
        "version": otto.get("version"),
        "fms_version": (fms.get("version") or {}).get("long"),
        "license_valid": otto.get("isLicenseValid"),
        "api_keys": _keys(raw["api_keys"]),
        "settings_readable": raw["settings"].get("ok", False),
    }


def collect(host, out_dir, allow_untrusted=False):
    creds = secrets.get(host, "otto") or secrets.get(host, "admin")
    if creds is None:
        raise SystemExit(f"No stored credentials for {host}. Run: python -m audit login {host}")
    url = f"https://{host}"
    session = ReadOnlySession()
    session.verify = not allow_untrusted
    raw = {"info": _fetch(session, url, ENDPOINTS["info"])}
    if not raw["info"]["ok"]:
        raise SystemExit("OttoFMS did not answer at /otto/api/info. It is probably not installed; set ottofms_installed: false in answers.yaml.")
    session.auth = creds
    for name in ("api_keys", "settings"):
        raw[name] = _fetch(session, url, ENDPOINTS[name])
    if raw["api_keys"].get("status") in (401, 403):
        raise SystemExit("OttoFMS refused the credentials. Run: python -m audit login <host> --otto")
    otto = normalize(raw, host)
    out = Path(out_dir)
    (out / "otto.json").write_text(json.dumps(otto, indent=2))
    return otto
