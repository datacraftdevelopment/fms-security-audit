---
name: fms-server-audit
description: Read FileMaker Server settings through the Admin API and evaluate the SRV rules. Use after fms-connect succeeds.
---

# Server audit

1. Run `python -m audit collect server <host> --out audits/<slug>/<date>/server.json`.
   The collector logs in with the keychain credentials, sends only GET requests, and logs out.
2. It reads: server version, hosted files with encryption status and enabled extended privileges, web technology settings (Data API, OData, WebDirect, XML, PHP), security settings such as host password-protected files only, schedules with their accounts and last results, plug-ins, certificate details where the API exposes them, and connected clients (used by FIL-08).
3. Anything the API doesn't return on this FMS version is recorded as missing, so its rule shows Not checked.
4. Run `python -m audit evaluate audits/<slug>/<date>/` and summarize the results for the consultant in a few lines.

For endpoint details, see the FileMaker Admin API reference skill in `.claude/skills/`.
