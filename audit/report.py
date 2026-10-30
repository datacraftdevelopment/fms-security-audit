"""Build the client report from findings.json. Every table comes from the findings; only
the executive summary (answers.yaml: summary) is written by a person."""

import datetime as dt
import json
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = Path(__file__).resolve().parent / "templates"


def _plan(results):
    order = {"fail": 0, "warn": 1}
    groups = {}
    for r in results:
        if r["status"] not in order:
            continue
        g = groups.setdefault(r["id"], {"id": r["id"], "title": r["title"], "remediation": r["remediation"], "rank": order[r["status"]], "scopes": []})
        g["rank"] = min(g["rank"], order[r["status"]])
        if r["scope"] not in ("server", "os"):
            g["scopes"].append(r["scope"])
    items = sorted(groups.values(), key=lambda g: (g["rank"], g["id"]))
    for g in items:
        g["scopes"] = ", ".join(g["scopes"])
    return items


def build(folder, out=None, sample=False):
    folder = Path(folder)
    findings = json.loads((folder / "findings.json").read_text())
    answers = yaml.safe_load((folder / "answers.yaml").read_text()) or {}
    results = findings["results"]
    files = {f["name"]: f for f in findings.get("files", [])}
    file_names = list(dict.fromkeys(r["scope"] for r in results if r["group"] == "files"))
    sections = []
    for name in file_names:
        rows = [r for r in results if r["scope"] == name]
        info = files.get(name)
        elevated = [a for a in (info or {}).get("accounts", []) if a.get("active") and (a.get("privilege_set") or "").lower() == "[full access]"]
        sections.append({"name": name, "rows": rows, "info": info, "elevated": elevated, "counts": {s: sum(r["status"] == s for r in rows) for s in ("fail", "warn", "pass", "nc")}})

    date = dt.date.fromisoformat(findings["audit_date"])
    os_facts = (findings.get("facts") or {}).get("os") or {}
    fms = (findings.get("facts") or {}).get("fms_version")
    platform = ", ".join(x for x in [os_facts.get("name"), f"FMS {fms}" if fms else None] if x) or "Not reported"
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    html = env.get_template("report.html.j2").render(
        client=findings.get("client") or "Client",
        server=findings.get("server") or "",
        consultant=answers.get("consultant"),
        firm=answers.get("firm") or "The consultant",
        date_long=f"{date.day} {date.strftime('%B %Y')}",
        platform=platform,
        ruleset=findings["ruleset"],
        summary=answers.get("summary"),
        counts=findings["counts"],
        total=len(results),
        server_rows=[r for r in results if r["group"] == "server"],
        os_rows=[r for r in results if r["group"] == "os"],
        file_sections=sections,
        file_rule_count=len({r["id"] for r in results if r["group"] == "files"}),
        fixed=findings.get("fixed_since_last") or [],
        plan=_plan(results),
        files=list(files.values()),
        plugins=(findings.get("facts") or {}).get("plugins"),
        sample=sample,
    )
    out = Path(out) if out else folder / "report.html"
    out.write_text(html)
    return out


def pdf(html_path):
    """Print the HTML report to PDF with Playwright if it is installed; otherwise print from a browser."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    pdf_path = Path(html_path).with_suffix(".pdf")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.emulate_media(color_scheme="light")
        page.goto(Path(html_path).resolve().as_uri())
        page.pdf(path=str(pdf_path), format="Letter", print_background=True, margin={"top": "0.6in", "bottom": "0.6in", "left": "0.6in", "right": "0.6in"})
        browser.close()
    return pdf_path
