"""Command-line entry point: python -m audit <command>"""

import argparse
import datetime as dt
import json
import re
import shutil
import sys
from pathlib import Path

from audit import clipboard, engine, osdata, report, secrets

ROOT = Path(__file__).resolve().parent.parent


def cmd_login(a):
    secrets.prompt_and_store(a.host, "admin")
    if a.otto:
        secrets.prompt_and_store(a.host, "otto")
    print("Stored in your keychain. Next: python -m audit check-connection " + a.host)


def cmd_logout(a):
    removed = secrets.delete(a.host)
    print(f"Removed stored credentials for {a.host}: {', '.join(removed) or 'none found'}.")


def cmd_check(a):
    from audit.collect import admin_api

    admin_api.check_connection(a.host, a.allow_untrusted_cert)
    print("Admin API login works.")


def cmd_new(a):
    slug = re.sub(r"[^a-z0-9]+", "-", a.client.lower()).strip("-")
    folder = ROOT / "audits" / slug / (a.date or dt.date.today().isoformat())
    if folder.exists():
        raise SystemExit(f"{folder} already exists.")
    shutil.copytree(ROOT / "audits" / "_template", folder)
    answers = folder / "answers.yaml"
    text = answers.read_text()
    text = text.replace('client: ""', f'client: "{a.client}"').replace('server: ""', f'server: "{a.server}"')
    answers.write_text(text)
    print(folder.relative_to(ROOT))


def cmd_collect(a):
    out = Path(a.out)
    if a.what == "server":
        from audit.collect import admin_api

        admin_api.collect(a.host, out, a.allow_untrusted_cert)
        print(f"Wrote {out / 'server.json'}")
    else:
        from audit.collect import ottofms

        ottofms.collect(a.host, out, a.allow_untrusted_cert)
        print(f"Wrote {out / 'otto.json'}")


def cmd_os_script(a):
    path = ROOT / "scripts" / ("os-audit-win.ps1" if a.platform == "win" else "os-audit-mac.sh")
    text = path.read_text()
    if not a.print and clipboard.copy(text):
        target = "PowerShell (Run as administrator)" if a.platform == "win" else "Terminal"
        print(f"The script is on your clipboard. Paste it into {target} in your remote desktop session.")
    else:
        print(text)


def cmd_os_import(a):
    text = Path(a.file).read_text() if a.file else (sys.stdin.read() if a.stdin else clipboard.paste())
    if not text:
        raise SystemExit("Nothing on the clipboard. Copy the block, or use --file or --stdin.")
    try:
        data = osdata.decode(text)
    except osdata.BlockError as exc:
        raise SystemExit(str(exc))
    out = Path(a.out) / "os.json"
    out.write_text(json.dumps(data, indent=2))
    skipped = data.get("not_checked") or {}
    print(f"Saved {out}. {len(skipped)} item(s) could not be read." if skipped else f"Saved {out}.")


def cmd_parse_xml(a):
    from audit.parse import fm_xml

    data = fm_xml.parse_folder(a.folder, delete=not a.keep_xml)
    (Path(a.folder) / "files.json").write_text(json.dumps(data, indent=2))
    for f in data["files"]:
        print(f"{f['name']}: {len(f['accounts'])} accounts, {len(f['privilege_sets'])} privilege sets")
    if not data["files"]:
        print("No XML files found in the xml/ folder.")


def cmd_evaluate(a):
    out = engine.run(a.folder, previous=a.previous)
    c = out["counts"]
    print(f"{c['fail']} fail, {c['warn']} warn, {c['pass']} pass, {c['nc']} not checked")


def cmd_report(a):
    engine.run(a.folder, previous=a.previous)
    html = report.build(a.folder)
    print(f"Wrote {html}")
    if a.pdf:
        made = report.pdf(html)
        print(f"Wrote {made}" if made else "Playwright isn't installed; open the HTML in a browser and print to PDF.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m audit", description="FileMaker security audit")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("login", help="store credentials in your keychain (run in your own terminal)")
    s.add_argument("host")
    s.add_argument("--otto", action="store_true", help="also store separate OttoFMS credentials (only if they differ from the Admin Console ones)")
    s.set_defaults(fn=cmd_login)

    s = sub.add_parser("logout", help="delete stored credentials")
    s.add_argument("host")
    s.set_defaults(fn=cmd_logout)

    s = sub.add_parser("check-connection", help="test the Admin API login")
    s.add_argument("host")
    s.add_argument("--allow-untrusted-cert", action="store_true")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("new", help="start an audit folder")
    s.add_argument("client")
    s.add_argument("--server", required=True)
    s.add_argument("--date")
    s.set_defaults(fn=cmd_new)

    s = sub.add_parser("collect", help="read settings from the server")
    s.add_argument("what", choices=["server", "otto"])
    s.add_argument("host")
    s.add_argument("--out", required=True)
    s.add_argument("--allow-untrusted-cert", action="store_true")
    s.set_defaults(fn=cmd_collect)

    s = sub.add_parser("os-script", help="copy the OS script to your clipboard")
    s.add_argument("platform", choices=["win", "mac"])
    s.add_argument("--print", action="store_true", help="print instead of copying")
    s.set_defaults(fn=cmd_os_script)

    s = sub.add_parser("os-import", help="save the OS script's result block")
    s.add_argument("--out", required=True)
    s.add_argument("--file")
    s.add_argument("--stdin", action="store_true")
    s.set_defaults(fn=cmd_os_import)

    s = sub.add_parser("parse-xml", help="read accounts from the XML exports")
    s.add_argument("folder")
    s.add_argument("--keep-xml", action="store_true")
    s.set_defaults(fn=cmd_parse_xml)

    s = sub.add_parser("evaluate", help="run the rules")
    s.add_argument("folder")
    s.add_argument("--previous")
    s.set_defaults(fn=cmd_evaluate)

    s = sub.add_parser("report", help="run the rules and build the report")
    s.add_argument("folder")
    s.add_argument("--previous")
    s.add_argument("--pdf", action="store_true")
    s.set_defaults(fn=cmd_report)

    a = p.parse_args(argv)
    a.fn(a)
    return 0
