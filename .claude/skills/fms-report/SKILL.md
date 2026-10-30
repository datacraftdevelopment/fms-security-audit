---
name: fms-report
description: Build the client report (HTML and PDF) from the findings, and compare with a previous audit if one exists. Use as the last step of an audit.
---

# Report

1. Run `python -m audit.report audits/<slug>/<date>/`. Add `--previous audits/<slug>/<earlier-date>/` when an earlier audit exists, so each finding is marked new, fixed or unchanged.
2. The report follows `docs/sample-report.html`: cover, executive summary, scope and method, server checklist, OS checklist, one section per file, remediation plan, appendix, and the disclaimer as the last section. Never remove or shorten the disclaimer.
3. Write the executive summary only: three to five plain sentences on the most serious findings. Do not change any status, table or count.
4. Show the consultant the totals and the Fail items, and ask them to read the whole report before sending it.
5. Output: `report.html`, `report.pdf` and `findings.json` in the audit folder.
