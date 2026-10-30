---
name: ottofms-audit
description: Read OttoFMS settings when OttoFMS is installed on the FileMaker Server. Skip when answers.yaml says it isn't.
---

# OttoFMS audit

1. Skip this step if `ottofms_installed` is false in `answers.yaml`. SRV-09 then shows Not checked.
2. Suggest the client create a temporary OttoFMS API key for the audit and revoke it afterwards.
3. Run `python -m audit.collect otto <host> --out audits/<slug>/<date>/otto.json` (read-only).
4. It reads the OttoFMS version and API keys with their expiry, plus deployment and backup settings where exposed.

For API details, see the OttoFMS admin reference skill in `.claude/skills/`.
