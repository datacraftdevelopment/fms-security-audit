---
name: ottofms-audit
description: Read OttoFMS settings when OttoFMS is installed on the FileMaker Server. Skip when answers.yaml says it isn't.
---

# OttoFMS audit

1. Skip this step if `ottofms_installed` is false in `answers.yaml`. SRV-09 then shows Not checked.
2. OttoFMS accepts the Admin Console login, so nothing extra is usually needed. If the client uses different OttoFMS credentials, the consultant runs `python -m audit login <host> --otto` in their own terminal.
3. Run `python -m audit collect otto <host> --out audits/<slug>/<date>/` (read-only). If it says OttoFMS did not answer, set `ottofms_installed: false`.
4. It writes `otto.json`: OttoFMS version, licence status, and each API key's label, file, created, last used and expiry. Key secrets are never saved.
5. SRV-09 warns about keys with no expiry date, expired keys still listed, and an invalid licence.

For API details, see the `ottofms-reference` skill.
