---
name: fms-audit
description: Run a complete FileMaker security audit for one client, start to finish. Use when the consultant asks what to do, or asks to start or continue an audit.
---

# Run a FileMaker security audit

Follow the walkthrough in `AGENTS.md`, one step at a time. This skill adds the details.

## Start

1. Ask for the client name, server hostname, and whether the server runs Windows or macOS.
2. Run `python -m audit new "<Client Name>" --server <host>`. It creates `audits/<slug>/<YYYY-MM-DD>/` from the template.
3. If an earlier audit folder exists for this client, note it; fms-report will compare against it.

## Judgment questions

Ask these once, in plain words, and record the answers in `answers.yaml`:

- Is OttoFMS installed?
- Which accounts belong to developers or administrators who genuinely need Full Access?
- Which privilege sets need the Data API (fmrest), OData (fmodata) or WebDirect (fmwebdirect)? If unsure, record none; the report will flag them for review.
- Are there privilege sets that should not be able to export or print?

## Order of steps

fms-connect → fms-server-audit → ottofms-audit (if installed) → fms-os-audit → fms-file-audit → fms-report.

Each step can be skipped if its access isn't available. Its checks then show as Not checked. Never stop the whole audit because one source is missing.

## Finish

Remind the consultant to run `python -m audit logout <host>` in their terminal, deliver the PDF, move the audit folder to secure storage, and ask the client to rotate any credentials they lent.
