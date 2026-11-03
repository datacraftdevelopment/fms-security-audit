"""Deterministic checks. Each returns (status, finding) for one scope.

Status is one of: pass, warn, fail, nc (Not checked). Text comes from the data only.
"""

import datetime as dt
import re
from collections import Counter

PASS, WARN, FAIL, NC = "pass", "warn", "fail", "nc"
FULL = "[full access]"


def _version(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])


def _days_until(date_str, today):
    return (dt.date.fromisoformat(date_str[:10]) - today).days


def _join(items):
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _failed(result):
    """True when a schedule's last result is a failure: a non-zero error code or a failure word."""
    if result is None or result == "":
        return False
    s = str(result).strip().lower()
    if s.lstrip("-").isdigit():
        return int(s) != 0
    return any(w in s for w in ("fail", "error", "abort"))


def _full_access_accounts(files):
    names = set()
    for f in files or []:
        for a in f["accounts"]:
            if a.get("active") and (a.get("privilege_set") or "").lower() == FULL:
                names.add(a["name"].lower())
    return names


# ---------- server ----------

def srv_01(ctx, p):
    v = (ctx.server or {}).get("version")
    if not v:
        return NC, "Version not reported by the Admin API."
    if _version(v) < _version(p["min_version"]):
        return FAIL, f"{v} is below the minimum safe version, {p['min_version']}."
    return PASS, f"{v}."


def srv_02(ctx, p):
    c = (ctx.server or {}).get("certificate")
    if not c or (c.get("trusted") is None and not c.get("expires")):
        return NC, "Certificate could not be read."
    issuer = c.get("issuer") or ""
    if any(d.lower() in issuer.lower() for d in p["default_issuers"]):
        return FAIL, "The default Claris certificate is installed."
    if c.get("trusted") is False:
        return FAIL, f"Certificate is not trusted: {c.get('error') or 'unknown reason'}."
    if c.get("expires"):
        days = _days_until(c["expires"], ctx.today)
        exp = dt.date.fromisoformat(c["expires"])
        when = f"{exp.day} {exp.strftime('%B %Y')}"
        if days < 0:
            return FAIL, f"Certificate expired on {when}."
        if days <= p["warn_days"]:
            return WARN, f"Trusted certificate, but expires {when} ({days} days)."
        return PASS, f"Trusted certificate, expires {when}."
    return PASS, "Trusted certificate."


def srv_03(ctx, p):
    files = (ctx.server or {}).get("files")
    if files is None:
        return NC, "Hosted files not reported by the Admin API."
    bad = [f["name"] for f in files if f.get("encrypted") is False]
    unknown = [f["name"] for f in files if f.get("encrypted") is None]
    if bad:
        return FAIL, f"{_join(bad)} {'is' if len(bad) == 1 else 'are'} not encrypted."
    if unknown:
        return NC, f"Encryption status not reported for {_join(unknown)}."
    return PASS, f"All {len(files)} hosted files are encrypted."


def srv_04(ctx, p):
    v = (ctx.server or {}).get("require_secure_db")
    if v is None:
        return NC, "Setting not reported by the Admin API."
    return (PASS, "Enabled.") if v else (FAIL, "Turned off: files without a password can be hosted.")


WEBTECH = {"dataapi": ("Data API", "data_api_sets"), "odata": ("OData", "odata_sets"), "webdirect": ("WebDirect", "webdirect_sets"), "xml": ("XML", None), "php": ("PHP", None)}


def srv_05(ctx, p):
    web = (ctx.server or {}).get("webtech") or {}
    if all(v is None for v in web.values()):
        return NC, "Web technology settings not reported by the Admin API."
    on = [k for k, v in web.items() if v]
    unneeded = [k for k in on if not (WEBTECH[k][1] and ctx.answers.get(WEBTECH[k][1]))]
    if unneeded:
        names = _join(WEBTECH[k][0] for k in unneeded)
        needed = [WEBTECH[k][0] for k in on if k not in unneeded]
        extra = f" {_join(needed)} {'is' if len(needed) == 1 else 'are'} in use." if needed else ""
        return FAIL, f"{names} {'is' if len(unneeded) == 1 else 'are'} on with no stated need.{extra}"
    if on:
        return PASS, f"Only what is in use is on: {_join(WEBTECH[k][0] for k in on)}."
    return PASS, "All web technologies are off."


def srv_06(ctx, p):
    sched = (ctx.server or {}).get("schedules")
    if sched is None:
        return NC, "Schedules not reported by the Admin API."
    backups = [s for s in sched if "backup" in str(s.get("type", "")).lower()]
    enabled = [s for s in backups if s.get("enabled") not in (False, "DISABLED", "disabled")]
    if not enabled:
        return FAIL, "No enabled backup schedule."
    failed = [s["name"] for s in enabled if _failed(s.get("last_result"))]
    if failed:
        return FAIL, f"Last run failed: {_join(failed)}."
    n = f"{len(enabled)} enabled backup schedule{'s' if len(enabled) > 1 else ''}"
    if all(s.get("last_result") in (None, "") for s in enabled):
        return PASS, f"{n}; the Admin API did not report the last result."
    return PASS, f"{n}, last run succeeded."


def srv_07(ctx, p):
    sched = (ctx.server or {}).get("schedules")
    if sched is None:
        return NC, "Schedules not reported by the Admin API."
    full = _full_access_accounts(ctx.files)
    risky = [s for s in sched if s.get("account") and (s["account"].lower() in full or s["account"].lower() == "admin")]
    if risky:
        return WARN, "; ".join(f"\"{s['name']}\" runs as {s['account']}, which has Full Access" for s in risky) + "."
    scripts = [s for s in sched if "script" in str(s.get("type", "")).lower()]
    n = f"{len(scripts)} script schedule{'s' if len(scripts) != 1 else ''}"
    if not scripts:
        return PASS, "No script schedules."
    named = sorted({s["account"] for s in scripts if s.get("account")})
    if not named:
        return NC, f"{n}, but the Admin API did not report which account runs them."
    if ctx.files is None:
        return NC, f"{n}, running as {_join(named)}. Provide the file exports to check whether those accounts have Full Access."
    return PASS, f"{n}, none run as a Full Access account."


def srv_08(ctx, p):
    plugins = (ctx.server or {}).get("plugins")
    if plugins is None:
        return NC, "Plug-ins not reported by the Admin API."
    return PASS, f"{len(plugins)} plug-in{'s' if len(plugins) != 1 else ''} installed, listed in the appendix for review."


def srv_09(ctx, p):
    if ctx.answers.get("ottofms_installed") is False:
        return NC, "OttoFMS is not installed."
    if not ctx.otto:
        return NC, "OttoFMS settings were not collected."
    o = ctx.otto
    problems = []
    if o.get("license_valid") is False:
        problems.append("the OttoFMS licence is not valid")
    keys = o.get("api_keys")
    if keys is None:
        return NC, f"OttoFMS {o.get('version') or ''} found, but its API keys could not be read.".replace("  ", " ")
    today = ctx.today.isoformat()
    no_expiry = [k.get("label") or "unnamed" for k in keys if not k.get("expiration")]
    expired = [k.get("label") or "unnamed" for k in keys if k.get("expiration") and str(k["expiration"])[:10] < today]
    if no_expiry:
        problems.append(f"{len(no_expiry)} API key{' never expires' if len(no_expiry) == 1 else 's never expire'} ({', '.join(no_expiry)})")
    if expired:
        problems.append(f"{len(expired)} expired API key{'s' if len(expired) != 1 else ''} still listed ({', '.join(expired)})")
    version = f"OttoFMS {o['version']}" if o.get("version") else "OttoFMS"
    if problems:
        return WARN, f"{version}: " + "; ".join(problems) + "."
    return PASS, f"{version}, {len(keys)} API key{'s' if len(keys) != 1 else ''}, all with an expiry date."


# ---------- operating system ----------

def _os_missing(ctx, key):
    if not ctx.os:
        return "The OS script was not run."
    if ctx.os.get(key) is None:
        return (ctx.os.get("not_checked") or {}).get(key) or "Not reported by the OS script."
    return None


def _public(listeners):
    return [l for l in listeners if not str(l.get("address", "")).startswith(("127.", "::1", "[::1]"))]


def os_01(ctx, p):
    if (m := _os_missing(ctx, "listeners")):
        return NC, m
    remote = set(ctx.params["OS-02"]["remote_ports"])
    odd = sorted({(l["port"], l.get("process")) for l in _public(ctx.os["listeners"]) if l["port"] not in p["expected_ports"] and l["port"] not in remote and l["port"] < p["ignore_from_port"]}, key=lambda x: x[0])
    if odd:
        parts = [f"{port}" + (f" ({proc})" if proc else "") for port, proc in odd]
        return WARN, f"Not part of FileMaker Server: {_join(parts)}."
    return PASS, "Only FileMaker Server ports are listening."


def os_02(ctx, p):
    if (m := _os_missing(ctx, "listeners")):
        return NC, m
    found = []
    for l in _public(ctx.os["listeners"]):
        proc = (l.get("process") or "").lower()
        if l["port"] in p["remote_ports"]:
            found.append(f"{p['remote_ports'][l['port']]} ({l['port']})")
        elif any(r in proc for r in p["remote_processes"]):
            found.append(f"{l['process']} ({l['port']})")
    found = sorted(set(found))
    if found:
        return WARN, f"{_join(found)} {'is' if len(found) == 1 else 'are'} listening. Confirm each is needed and limited to known users."
    return PASS, "No remote access services listening."


def os_03(ctx, p):
    if (m := _os_missing(ctx, "firewall")):
        return NC, m
    fw = ctx.os["firewall"]
    off = [pr["name"] for pr in fw.get("profiles", []) if pr.get("enabled") is False]
    if off:
        return FAIL, f"The {_join(off)} firewall profile{'s are' if len(off) > 1 else ' is'} turned off."
    expected = set(ctx.params["OS-01"]["expected_ports"])
    broad = [r for r in fw.get("broad_allow_rules", []) if not {int(x) for x in re.findall(r"\d+", r["ports"])} <= expected]
    if broad:
        return WARN, f"Inbound rules open to any address: {_join(r['name'] + ' (' + r['ports'] + ')' for r in broad[:5])}."
    return PASS, "Firewall on, no broad inbound rules beyond FileMaker."


def os_04(ctx, p):
    if (m := _os_missing(ctx, "os")):
        return NC, m
    name = ctx.os["os"].get("name") or ""
    if ctx.os.get("platform") == "mac":
        major = _version(ctx.os["os"].get("version") or "0")[:1] or (0,)
        if major[0] < p["min_macos_major"]:
            return FAIL, f"{name} {ctx.os['os'].get('version')} is no longer supported."
        return PASS, f"{name} {ctx.os['os'].get('version')}, still supported."
    for label, end in p["windows_end_of_support"].items():
        if label.lower() in name.lower():
            short = label
            if _days_until(end, ctx.today) < 0:
                return FAIL, f"{short} is past end of support."
            return PASS, f"{short}, still supported."
    return NC, f"Support status unknown for {name}."


def os_05(ctx, p):
    if (m := _os_missing(ctx, "patching")):
        return NC, m
    pat = ctx.os["patching"]
    if not pat.get("last_installed"):
        return NC, "Last update date not reported."
    age = -_days_until(pat["last_installed"], ctx.today)
    notes = []
    if age > p["max_days"]:
        notes.append(f"Last update installed {age} days ago.")
    if pat.get("auto_updates") is False:
        notes.append("Automatic updates are off.")
    if notes:
        return WARN, " ".join(notes)
    return PASS, f"Last update installed {age} days ago."


def os_06(ctx, p):
    if (m := _os_missing(ctx, "local_admins")):
        return NC, m
    admins = ctx.os["local_admins"]
    shared = [a for a in admins if a.split("\\")[-1].lower() in p["shared_names"]]
    if shared:
        names = _join(a.split("\\")[-1] for a in shared)
        return WARN, f"{len(admins)} members, including shared account{'s' if len(shared) > 1 else ''} named {names}."
    return PASS, f"{len(admins)} members, all named accounts."


def os_07(ctx, p):
    if not ctx.os:
        return NC, "The OS script was not run."
    disks = ctx.os.get("disk_encryption")
    if disks is None:
        reason = (ctx.os.get("not_checked") or {}).get("disk_encryption") or ""
        if "not installed" in reason.lower():
            return WARN, "BitLocker is not installed, so the disks are not encrypted with it."
        return NC, reason or "Not reported by the OS script."
    off = [d["volume"] for d in disks if d.get("encrypted") is False]
    if off:
        return WARN, f"Not encrypted: {_join(off)}."
    if any(d.get("encrypted") is None for d in disks):
        return NC, "Encryption status could not be read."
    tool = "FileVault" if ctx.os.get("platform") == "mac" else "BitLocker"
    return PASS, f"{tool} on for {_join(d['volume'] for d in disks)}."


def os_08(ctx, p):
    if (m := _os_missing(ctx, "antivirus")):
        return NC, m
    products = ctx.os["antivirus"].get("products") or []
    running = [x for x in products if x.get("running")]
    if not running:
        return FAIL, "No antivirus found running."
    stale = [x for x in running if x.get("signature_age_days") is not None and x["signature_age_days"] > p["max_signature_age_days"]]
    if stale:
        return WARN, f"{stale[0]['name']} signatures are {stale[0]['signature_age_days']} days old."
    first = running[0]
    age = f", signatures {first['signature_age_days']} day{'s' if first['signature_age_days'] != 1 else ''} old" if first.get("signature_age_days") is not None else ""
    return PASS, f"{first['name']} running{age}."


def os_09(ctx, p):
    if (m := _os_missing(ctx, "av_exclusions")):
        return NC, m
    data = ctx.os.get("fms_data_paths") or []
    if not data:
        return NC, "FileMaker data folder not found at the default location."
    excl = [e.lower().rstrip("\\/") for e in ctx.os["av_exclusions"]]
    if any(d.lower().rstrip("\\/").startswith(tuple(excl)) for d in data if excl):
        return PASS, "The live database folder is excluded from real-time scanning."
    return WARN, "The live database folder is not excluded from real-time scanning, which Claris recommends."


# ---------- files ----------

def _active(f):
    return [a for a in f["accounts"] if a.get("active") and a["name"].strip("[]").lower() != "guest"]


def fil_01(ctx, f, p):
    if not f["accounts"]:
        return NC, "No accounts found in the export."
    dev = {d.lower() for d in ctx.answers.get("developer_accounts") or []}
    active = _active(f)
    full = [a for a in active if (a.get("privilege_set") or "").lower() == FULL]
    staff = [a for a in full if a["name"].lower() not in dev]
    if len(full) > p["max_full_access"] or staff:
        extra = f", including {len(staff)} staff account{'s' if len(staff) != 1 else ''}" if staff else ""
        return FAIL, f"{len(full)} of {len(active)} active accounts have Full Access{extra}."
    return PASS, f"{len(full)} Full Access account{'s' if len(full) != 1 else ''}, all developers or administrators."


def fil_02(ctx, f, p):
    if not f["accounts"]:
        return NC, "No accounts found in the export."
    hits = [a["name"] for a in _active(f) if a["name"].lower() in p["default_names"]]
    if hits:
        return FAIL, f"An active account named {_join(hits)}."
    return PASS, "No default account names in use."


def fil_03(ctx, f, p):
    if f.get("guest_enabled") is None:
        return NC, "Guest account not found in the export."
    if f["guest_enabled"]:
        return FAIL, "Guest is enabled, so anyone who can reach the server can open the file without a password."
    return PASS, "Disabled."


def fil_04(ctx, f, p):
    active = _active(f)
    if not active:
        return NC, "No active accounts found."
    name, count = Counter(a.get("privilege_set") for a in active).most_common(1)[0]
    share = count / len(active)
    ps = next((s for s in f["privilege_sets"] if s["name"] == name), {})
    broad = (name or "").lower() == FULL or ps.get("broad_delete")
    if share > p["share_threshold"] or (broad and share >= 0.5):
        return FAIL, f"{round(share * 100)}% of active accounts share {name}."
    return PASS, f"Largest group is {round(share * 100)}% on {name}."


def _dev_sets(ctx, f):
    dev = {d.lower() for d in ctx.answers.get("developer_accounts") or []}
    return {a.get("privilege_set") for a in f["accounts"] if a["name"].lower() in dev} | {"[Full Access]"}


def fil_05(ctx, f, p):
    if not f["privilege_sets"]:
        return NC, "No privilege sets found in the export."
    parts = {"layouts_modify": "layouts", "scripts_modify": "scripts", "value_lists_modify": "value lists"}
    dev_sets = _dev_sets(ctx, f)
    issues = []
    for s in f["privilege_sets"]:
        if s["name"] in dev_sets or s["name"].startswith("["):
            continue
        rights = []
        mods = [label for k, label in parts.items() if s.get(k)]
        if mods:
            rights.append("modify " + _join(mods))
        if s.get("manage_accounts"):
            rights.append("manage accounts")
        if rights:
            issues.append(f"\"{s['name']}\" can {_join(rights)}")
    if issues:
        return WARN, "; ".join(issues) + "."
    return PASS, "No non-developer set can change the file's design or accounts."


def fil_06(ctx, f, p):
    restricted = set(ctx.answers.get("export_denied_sets") or [])
    if not restricted:
        return NC, "The client did not name any privilege sets that should be unable to export or print."
    bad = [s["name"] for s in f["privilege_sets"] if s["name"] in restricted and (s.get("export") or s.get("print"))]
    if bad:
        return WARN, f"Export or print allowed in {_join(bad)}, which should be restricted."
    return PASS, f"Matches what {ctx.answers.get('client') or 'the client'} asked for."


def fil_07(ctx, f, p):
    allowed = {
        "fmrest": set(ctx.answers.get("data_api_sets") or []),
        "fmodata": set(ctx.answers.get("odata_sets") or []),
        "fmwebdirect": set(ctx.answers.get("webdirect_sets") or []),
        "fmxml": set(),
    }
    hits = []
    for s in f["privilege_sets"]:
        for priv in s.get("ext_privs") or []:
            if priv in p["watched"] and s["name"] not in allowed.get(priv, set()):
                hits.append(f"{priv} on \"{s['name']}\"")
    if hits:
        return FAIL, f"Granted without a stated need: {_join(hits)}."
    return PASS, "Web and API access only where needed."


def fil_08(ctx, f, p):
    clients = (ctx.server or {}).get("clients")
    if clients is None:
        return NC, "Connected clients not reported by the Admin API."
    names = {a["name"].lower() for a in f["accounts"]}
    machines = {}
    for c in clients:
        acc = (c.get("account") or "").lower()
        if acc in names:
            machines.setdefault(c["account"], set()).add(c.get("machine"))
    shared = {a: m for a, m in machines.items() if len(m) > 1}
    if shared:
        return WARN, "; ".join(f"\"{a}\" was connected from {len(m)} machines" for a, m in shared.items()) + " at the time of the audit."
    return PASS, "No shared logins seen at the time of the audit."


def fil_09(ctx, f, p):
    ext = [a["name"] for a in f["accounts"] if "external" in str(a.get("type", "")).lower() or "group" in str(a.get("type", "")).lower()]
    if ext:
        return WARN, f"{len(ext)} external account{'s' if len(ext) != 1 else ''}; review group membership in the directory."
    return PASS, "No external accounts."


SERVER = {"SRV-01": srv_01, "SRV-02": srv_02, "SRV-03": srv_03, "SRV-04": srv_04, "SRV-05": srv_05, "SRV-06": srv_06, "SRV-07": srv_07, "SRV-08": srv_08, "SRV-09": srv_09}
OS = {"OS-01": os_01, "OS-02": os_02, "OS-03": os_03, "OS-04": os_04, "OS-05": os_05, "OS-06": os_06, "OS-07": os_07, "OS-08": os_08, "OS-09": os_09}
FILES = {"FIL-01": fil_01, "FIL-02": fil_02, "FIL-03": fil_03, "FIL-04": fil_04, "FIL-05": fil_05, "FIL-06": fil_06, "FIL-07": fil_07, "FIL-08": fil_08, "FIL-09": fil_09}
