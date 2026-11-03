import json
import shutil
from pathlib import Path

import pytest

from audit import engine, osdata, report
from audit.http import ReadOnlySession, WriteBlocked
from audit.parse import fm_xml

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "example-co"


@pytest.fixture
def audit_dir(tmp_path):
    folder = tmp_path / "example-co"
    shutil.copytree(SAMPLE, folder)
    data = fm_xml.parse_folder(folder)
    (folder / "files.json").write_text(json.dumps(data))
    return folder


def test_session_blocks_writes():
    s = ReadOnlySession()
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(WriteBlocked):
            s.request(method, "https://fms.example.com/fmi/admin/api/v2/databases/1")
    with pytest.raises(WriteBlocked):
        s.request("PATCH", "https://fms.example.com/fmi/admin/api/v2/server/config/general")


def test_session_allows_login_and_logout_paths_only():
    from audit.http import ALLOWED_WRITES

    assert any(m == "POST" and rx.search("/fmi/admin/api/v2/user/auth") for m, rx in ALLOWED_WRITES)
    assert any(m == "DELETE" and rx.search("/fmi/admin/api/v2/user/auth/abc123") for m, rx in ALLOWED_WRITES)
    assert not any(rx.search("/fmi/admin/api/v2/databases/1") for _, rx in ALLOWED_WRITES)


def test_os_block_round_trip_and_tamper():
    data = {"platform": "windows", "listeners": [{"port": 443}]}
    block = osdata.encode(data)
    assert osdata.decode("noise before\n" + block + "\nnoise after") == data
    lines = block.splitlines()
    lines[1] = lines[1][:-4] + "AAAA"
    with pytest.raises(osdata.BlockError):
        osdata.decode("\n".join(lines))
    with pytest.raises(osdata.BlockError):
        osdata.decode(block.split("sha256")[0])


def test_parser_reads_sample(audit_dir):
    files = {f["name"]: f for f in json.loads((audit_dir / "files.json").read_text())["files"]}
    inv = files["Invoices.fmp12"]
    assert sum(a["privilege_set"] == "[Full Access]" and a["active"] for a in inv["accounts"]) == 9
    staff = next(s for s in inv["privilege_sets"] if s["name"] == "Staff")
    assert staff["layouts_modify"] and "fmrest" in staff["ext_privs"]
    assert files["Contacts.fmp12"]["guest_enabled"] is True
    assert files["Inventory.fmp12"]["guest_enabled"] is False
    assert not list((audit_dir / "xml").glob("*.xml")), "XML should be deleted after parsing"


def test_sample_findings_are_stable(audit_dir):
    out = engine.run(audit_dir)
    assert out["counts"] == {"fail": 10, "warn": 11, "pass": 24, "nc": 0}
    status = {(r["id"], r["scope"]): r["status"] for r in out["results"]}
    assert status[("SRV-01", "server")] == "fail"
    assert status[("OS-03", "os")] == "fail"
    assert status[("FIL-03", "Contacts.fmp12")] == "fail"
    assert status[("FIL-01", "Inventory.fmp12")] == "pass"


def test_missing_sources_are_not_checked(tmp_path):
    folder = tmp_path / "empty"
    folder.mkdir()
    (folder / "answers.yaml").write_text("client: Test\naudit_date: 2026-10-30\n")
    out = engine.run(folder)
    assert all(r["status"] == "nc" for r in out["results"])


def test_reaudit_marks_fixed(audit_dir, tmp_path):
    engine.run(audit_dir)
    later = tmp_path / "later"
    shutil.copytree(audit_dir, later)
    files = json.loads((later / "files.json").read_text())
    for f in files["files"]:
        for a in f["accounts"]:
            if a["name"] == "[Guest]":
                a["active"] = False
    files_by = {f["name"]: f for f in files["files"]}
    files_by["Contacts.fmp12"]["guest_enabled"] = False
    (later / "files.json").write_text(json.dumps(files))
    out = engine.run(later, previous=audit_dir)
    assert any(r["id"] == "FIL-03" and r["scope"] == "Contacts.fmp12" for r in out["fixed_since_last"])


def test_report_renders_with_disclaimer_last(audit_dir):
    engine.run(audit_dir)
    html = report.build(audit_dir).read_text()
    assert "Example Co" in html
    assert html.rfind("<h2>Disclaimer</h2>") > html.rfind("<h2>Appendix</h2>")
    assert "does not manage, monitor or take responsibility" in html


def test_published_sample_report_is_current(audit_dir, tmp_path):
    engine.run(audit_dir)
    fresh = report.build(audit_dir, out=tmp_path / "sample.html", sample=True).read_text()
    assert fresh == (ROOT / "docs" / "sample-report.html").read_text(), "Regenerate with: python scripts/build_sample.py"


def test_otto_keeps_no_key_secrets():
    from audit.collect import ottofms

    raw = {
        "info": {"ok": True, "data": {"Otto": {"version": "4.18.2", "isLicenseValid": True}, "FileMakerServer": {"version": {"long": "22.0.4"}}}},
        "api_keys": {"ok": True, "data": {"api-keys": [{"label": "k", "key": "SECRET", "expiration": None}]}},
        "settings": {"ok": False},
    }
    out = ottofms.normalize(raw, "h")
    assert "SECRET" not in str(out)
    assert out["version"] == "4.18.2" and out["api_keys"][0]["label"] == "k"


def test_otto_html_catch_all_is_not_an_answer():
    from audit.collect import ottofms

    class Resp:
        status_code = 200
        headers = {"Content-Type": "text/html"}

    class S:
        def get(self, url):
            return Resp()

    assert ottofms._fetch(S(), "https://h", "/otto/api/nope")["ok"] is False


FM26_FIXTURE = Path(__file__).parent / "fixtures" / "saxml-fm26-accounts.xml"


@pytest.mark.skipif(not FM26_FIXTURE.exists(), reason="scrubbed FileMaker 26 export not present in tests/fixtures/")
def test_real_fm26_export():
    from audit.parse import fm_xml

    out = fm_xml.parse_file(FM26_FIXTURE)
    accounts = {a["name"]: a for a in out["accounts"]}
    assert accounts["Admin"] == {"name": "Admin", "privilege_set": "[Full Access]", "active": True, "type": "FileMaker"}
    assert accounts["[Guest]"]["active"] is False and out["guest_enabled"] is False
    sets = {s["name"]: s for s in out["privilege_sets"]}
    assert sets["[Data Entry Only]"]["broad_delete"] is True and sets["[Data Entry Only]"]["layouts_modify"] is False
    assert sets["[Full Access]"]["manage_accounts"] is True
    assert "PasswordEncrypted" not in str(out) and "REDACTED" not in str(out)


# ---- regression tests for the 0.1 review


def _ctx(**kw):
    import datetime as dt

    return engine.Context(answers=kw.pop("answers", {}), today=dt.date(2026, 10, 30), **kw)


def _params(rid):
    return engine.load_rules()[rid]["params"]


def test_backup_rule_reads_numeric_error_codes():
    from audit import rules

    sched = [{"name": "Daily backup", "type": "BACKUP", "enabled": True, "last_result": 1}]
    assert rules.srv_06(_ctx(server={"schedules": sched}), _params("SRV-06"))[0] == "fail"
    sched[0]["last_result"] = 0
    assert rules.srv_06(_ctx(server={"schedules": sched}), _params("SRV-06"))[0] == "pass"
    sched[0]["last_result"] = None
    status, text = rules.srv_06(_ctx(server={"schedules": sched}), _params("SRV-06"))
    assert status == "pass" and "did not report" in text


def test_script_schedule_rule_does_not_guess():
    from audit import rules

    scripts = [{"name": "Nightly import", "type": "FILEMAKER_SCRIPT", "enabled": True, "account": None}]
    assert rules.srv_07(_ctx(server={"schedules": scripts}), _params("SRV-07"))[0] == "nc"
    scripts[0]["account"] = "importer"
    assert rules.srv_07(_ctx(server={"schedules": scripts}, files=None), _params("SRV-07"))[0] == "nc"
    assert rules.srv_07(_ctx(server={"schedules": scripts}, files=[]), _params("SRV-07"))[0] == "pass"
    scripts[0]["account"] = "Admin"
    assert rules.srv_07(_ctx(server={"schedules": scripts}, files=None), _params("SRV-07"))[0] == "warn"


def test_admin_api_maps_filemaker_script_type():
    from audit.collect import admin_api

    raw = {"schedules": {"ok": True, "data": {"schedules": [
        {"name": "Nightly import", "taskType": "FILEMAKER_SCRIPT", "enabled": True, "filemakerScriptType": {"fmScriptAccount": "importer"}, "lastError": 0},
    ]}}}
    s = admin_api.normalize(raw, "h")["schedules"][0]
    assert s["account"] == "importer" and s["last_result"] == 0


def test_admin_api_tolerates_html_with_200():
    from audit.collect import admin_api

    class Resp:
        status_code = 200

        def json(self):
            raise ValueError("not json")

    class S:
        def get(self, url):
            return Resp()

    raw = admin_api.fetch_all(S(), "https://h")
    assert all(not v["ok"] for v in raw.values())


def test_export_rule_needs_an_answer():
    from audit import rules

    f = {"name": "X.fmp12", "accounts": [], "privilege_sets": [{"name": "Staff", "export": True, "print": True, "ext_privs": []}], "guest_enabled": False}
    assert rules.fil_06(_ctx(), f, _params("FIL-06"))[0] == "nc"
    assert rules.fil_06(_ctx(answers={"export_denied_sets": ["Staff"]}), f, _params("FIL-06"))[0] == "warn"


def test_os_block_scalars_become_lists():
    from audit import rules

    one = {"platform": "windows", "disk_encryption": {"volume": "C:", "encrypted": True}, "local_admins": "FMS01\\Administrator",
           "av_exclusions": "C:\\FMS\\Data\\Databases", "fms_data_paths": "C:\\FMS\\Data\\Databases", "antivirus": {"products": {"name": "Defender", "running": True}}}
    data = osdata.decode(osdata.encode(one))
    assert data["local_admins"] == ["FMS01\\Administrator"] and data["disk_encryption"] == [{"volume": "C:", "encrypted": True}]
    assert data["antivirus"]["products"][0]["name"] == "Defender"
    assert rules.os_06(_ctx(os=data), _params("OS-06"))[1].startswith("1 member")
    assert rules.os_07(_ctx(os=data), _params("OS-07"))[0] == "pass"
    assert rules.os_09(_ctx(os=data), _params("OS-09"))[0] == "pass"


def test_file_names_match_with_or_without_extension():
    f = {"name": "Contacts.fmp12", "accounts": [{"name": "a", "privilege_set": "Staff", "active": True, "type": "FileMaker"}], "privilege_sets": [], "guest_enabled": False}
    res = engine.evaluate(_ctx(server={"files": [{"name": "Contacts", "encrypted": True}]}, files=[f]))
    assert {r["scope"] for r in res if r["group"] == "files"} == {"Contacts.fmp12"}
    fixed = engine.compare([{"id": "FIL-03", "scope": "Contacts.fmp12", "status": "pass"}], [{"id": "FIL-03", "scope": "Contacts", "status": "fail"}])
    assert len(fixed) == 1


def test_parse_folder_deletes_nothing_when_one_export_is_bad(tmp_path):
    xml = tmp_path / "xml"
    xml.mkdir()
    shutil.copy(SAMPLE / "xml" / "Contacts.xml", xml / "Contacts.xml")
    (xml / "Zbroken.xml").write_text("<not closed")
    with pytest.raises(Exception):
        fm_xml.parse_folder(tmp_path)
    assert sorted(p.name for p in xml.glob("*.xml")) == ["Contacts.xml", "Zbroken.xml"]


def test_new_audit_quotes_client_name_and_sets_date(tmp_path, monkeypatch, capsys):
    import argparse

    import yaml

    from audit import cli

    shutil.copytree(ROOT / "audits" / "_template", tmp_path / "audits" / "_template")
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    cli.cmd_new(argparse.Namespace(client='Acme "Widgets" & Sons: Ltd', server="fms.acme.test", date="2026-11-03"))
    answers = yaml.safe_load((tmp_path / "audits" / "acme-widgets-sons-ltd" / "2026-11-03" / "answers.yaml").read_text())
    assert answers["client"] == 'Acme "Widgets" & Sons: Ltd'
    assert str(answers["audit_date"]) == "2026-11-03"
    with pytest.raises(SystemExit):
        cli.cmd_new(argparse.Namespace(client="Bad Date", server="h", date="3 Nov 2026"))
