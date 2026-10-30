"""Regenerate docs/sample-report.html from samples/example-co (fictitious data)."""

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit import engine, report  # noqa: E402
from audit.parse import fm_xml  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp) / "example-co"
    shutil.copytree(ROOT / "samples" / "example-co", folder)
    (folder / "files.json").write_text(json.dumps(fm_xml.parse_folder(folder)))
    engine.run(folder)
    out = report.build(folder, out=ROOT / "docs" / "sample-report.html", sample=True)
    print(f"Wrote {out.relative_to(ROOT)}")
