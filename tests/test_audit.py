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
    assert out["counts"] == {"fail": 10, "warn": 10, "pass": 24, "nc": 1}
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
