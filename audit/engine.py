"""Run every rule over the collected data and write findings.json."""

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from audit import RULESET_VERSION, rules

ROOT = Path(__file__).resolve().parent.parent
RULE_FILES = {"server": "server.yaml", "os": "os.yaml", "files": "files.yaml"}


@dataclass
class Context:
    answers: dict
    server: dict | None = None
    os: dict | None = None
    files: list | None = None
    otto: dict | None = None
    today: dt.date = field(default_factory=dt.date.today)
    params: dict = field(default_factory=dict)


def load_rules():
    meta = {}
    for group, name in RULE_FILES.items():
        for r in yaml.safe_load((ROOT / "rules" / name).read_text()):
            r.setdefault("params", {})
            r["group"] = group
            meta[r["id"]] = r
    return meta


def _read(folder, name):
    path = folder / name
    return json.loads(path.read_text()) if path.exists() else None


def load_context(folder, today=None):
    folder = Path(folder)
    answers = yaml.safe_load((folder / "answers.yaml").read_text()) or {}
    files = _read(folder, "files.json")
    ctx = Context(
        answers=answers,
        server=_read(folder, "server.json"),
        os=_read(folder, "os.json"),
        files=files["files"] if files else None,
        otto=_read(folder, "otto.json"),
    )
    if today:
        ctx.today = today
    elif answers.get("audit_date"):
        ctx.today = dt.date.fromisoformat(str(answers["audit_date"]))
    return ctx


def evaluate(ctx):
    meta = load_rules()
    ctx.params = {rid: m["params"] for rid, m in meta.items()}
    results = []

    def add(rid, scope, outcome):
        status, finding = outcome
        m = meta[rid]
        results.append({"id": rid, "title": m["title"], "group": m["group"], "scope": scope, "status": status, "finding": finding, "remediation": m["remediation"]})

    for rid, fn in rules.SERVER.items():
        add(rid, "server", fn(ctx, meta[rid]["params"]))
    for rid, fn in rules.OS.items():
        add(rid, "os", fn(ctx, meta[rid]["params"]))

    hosted = [f["name"] for f in (ctx.server or {}).get("files") or []]
    parsed = {f["name"]: f for f in ctx.files or []}
    for name in hosted + [n for n in parsed if n not in hosted]:
        f = parsed.get(name)
        for rid, fn in rules.FILES.items():
            add(rid, name, fn(ctx, f, meta[rid]["params"]) if f else (rules.NC, "No XML export was provided for this file."))
    return results


def compare(results, previous):
    """Mark each warn/fail as new or unchanged, and list what was fixed since the last audit."""
    before = {(r["id"], r["scope"]): r["status"] for r in previous}
    for r in results:
        old = before.get((r["id"], r["scope"]))
        if r["status"] in ("warn", "fail"):
            r["change"] = "unchanged" if old in ("warn", "fail") else "new"
    fixed = [r for r in previous if r["status"] in ("warn", "fail") and next((x["status"] for x in results if (x["id"], x["scope"]) == (r["id"], r["scope"])), None) == "pass"]
    return fixed


def run(folder, previous=None, today=None):
    folder = Path(folder)
    ctx = load_context(folder, today)
    results = evaluate(ctx)
    fixed = []
    if previous:
        prev = json.loads((Path(previous) / "findings.json").read_text())
        fixed = compare(results, prev["results"])
    counts = {s: sum(r["status"] == s for r in results) for s in ("fail", "warn", "pass", "nc")}
    out = {
        "client": ctx.answers.get("client"),
        "server": ctx.answers.get("server") or (ctx.server or {}).get("host"),
        "audit_date": ctx.today.isoformat(),
        "ruleset": RULESET_VERSION,
        "counts": counts,
        "results": results,
        "fixed_since_last": fixed,
        "facts": {"os": (ctx.os or {}).get("os"), "fms_version": (ctx.server or {}).get("version"), "plugins": (ctx.server or {}).get("plugins")},
        "files": ctx.files or [],
    }
    (folder / "findings.json").write_text(json.dumps(out, indent=2))
    return out
