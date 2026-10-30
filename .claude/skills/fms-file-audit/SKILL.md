---
name: fms-file-audit
description: Audit accounts, privilege sets and extended privileges in each hosted FileMaker file from an accounts-only Save as XML export. Use for the per-file audit.
---

# File audit

1. List the hosted files from `server.json` so nothing is missed.
2. For each file, the consultant (or the client) exports an accounts-only XML:
   - Open the file in FileMaker Pro, signed in with a Full Access account.
   - Save a Copy as XML, with only accounts and security information selected.
   - Save it as `<FileName>.xml` in `audits/<slug>/<date>/xml/`.
   If the client is doing it, write them short instructions they can follow without help.
3. Run `python -m audit parse-xml audits/<slug>/<date>/`. It reads each XML into `files.json` (accounts, privilege sets, extended privileges; never passwords, which aren't exported) and then deletes the XML files.
4. Run `python -m audit evaluate audits/<slug>/<date>/`.
5. Report any hosted file with no XML; its checks show as Not checked.

Never paste XML content into the chat beyond what's needed to debug the parser. For the XML structure, see the FileMaker XML reference skill in `.claude/skills/`.
