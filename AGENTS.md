# FileMaker Security Audit: agent instructions

You are helping a FileMaker consultant run a best-practice security audit of one client's FileMaker Server and the files it hosts. The person you're talking to may never have done this before and may not have any FileMaker skills or tools installed. Everything they need is in this repo.

These instructions are shared by Claude Code (via `CLAUDE.md`) and Codex (which reads this file directly).

## Ground rules (never break these)

1. **Never ask for, accept or repeat a password in the chat.** Credentials are entered only at the local prompt: `python -m audit.login <host>`, run by the consultant in their own terminal. If a password appears in the conversation, stop and tell the consultant to have it changed.
2. **Install nothing on the client's server and change nothing there.** All FileMaker Server reads are GET requests over HTTPS. The OS check is a read-only script the consultant pastes into their own remote desktop session.
3. **No testing from outside the network.** No port scans, probes or penetration testing. That is out of scope for this repo.
4. **Client data stays in `audits/`, which git ignores.** Never move client files elsewhere in the repo, never `git add` anything under `audits/`, and never paste raw XML or exports into commits, issues or pull requests.
5. **Rules decide, you explain.** Pass, Warn, Fail and Not checked come from the rule files in `rules/`. You may write the executive summary. Do not change a status by hand; if a result looks wrong, fix the input or raise the rule.

## When the consultant asks "what do I do?"

Walk them through it one step at a time. Don't dump the whole list. Ask, wait for the answer, then move on. Keep each message short.

1. **Check prerequisites.** Ask whether they have each of these, and explain any they don't understand:
   - Network reach to the server from this computer (office network or VPN). A quick test: can they open the Admin Console in a browser?
   - FileMaker Server Admin Console username and password.
   - OttoFMS admin login or API key, only if OttoFMS is installed.
   - Remote desktop access to the server: RDP for Windows, Screen Sharing or similar for Mac. Admin rights are best.
   - A Full Access login for each hosted file, or a client admin willing to export the XML.
   - Python 3.10 or later on this computer (`python --version`). If missing, help them install it, then run `pip install -r requirements.txt`.
2. **Start the audit folder.** Ask for the client name and server hostname. Create `audits/<client-slug>/<YYYY-MM-DD>/` by copying `audits/_template/`. Tell them where it is.
3. **Ask the judgment questions** in `.claude/skills/fms-audit/SKILL.md` (which accounts are developers, which privilege sets need the Data API, OData or WebDirect) and save the answers to `answers.yaml` in the audit folder.
4. **Log in locally.** Tell them to open a separate terminal and run `python -m audit.login <host>`. Wait until they say it worked.
5. **Collect server settings** with the fms-server-audit skill, then ottofms-audit if OttoFMS is installed.
6. **OS check.** Follow the fms-os-audit skill: copy the right script to their clipboard, explain how to paste it in PowerShell (Windows) or Terminal (Mac) inside their remote desktop session, then import the result with `python -m audit.os-import`.
7. **File XML.** Follow the fms-file-audit skill: explain how to Save a Copy as XML with accounts only for each hosted file into the audit folder's `xml/` subfolder. Offer client-ready instructions if someone else is doing the export.
8. **Report.** Run fms-report. Show the counts, walk them through the Fail items, and let them edit the summary.
9. **Close out.** Remind them to run `python -m audit.logout <host>`, deliver the PDF, store the audit folder securely, and ask the client to rotate the credentials they lent.

If they get stuck, the human-readable version of all of this is `docs/consultant-guide.html`.

## Repo map

| Path | What it is |
| --- | --- |
| `README.md` | Start here (for people browsing GitHub) |
| `docs/consultant-guide.html` | Step-by-step guide for consultants |
| `docs/sample-report.html` | What the client receives (fictitious data) |
| `.claude/skills/` | All skills. Claude Code loads them automatically; in Codex, read the `SKILL.md` for the step you're on |
| `audit/` | Python package: collectors, XML parser, rules engine, report builder |
| `rules/` | Rule definitions and thresholds (server, OS, file) |
| `checklists/best-practices.md` | The human-readable standard the rules implement |
| `scripts/` | The read-only OS scripts (PowerShell and shell) |
| `audits/` | Client work, git-ignored. One folder per client per date, each with an `xml/` folder for the exports |
| `samples/example-co/` | Fictitious inputs used for tests and the sample report |
| `tests/` | Tests, including a check that collectors only send GET requests |

## Skills

| Skill | Use it for |
| --- | --- |
| fms-audit | The whole audit, start to finish. Default entry point |
| fms-connect | Testing logins after `audit.login` |
| fms-server-audit | FileMaker Server settings via the Admin API |
| ottofms-audit | OttoFMS settings, if installed |
| fms-os-audit | The paste-in OS script and importing its result |
| fms-file-audit | Accounts-only XML: accounts, privilege sets, extended privileges |
| fms-report | Building the HTML and PDF report |

Reference skills (FileMaker Admin API, OttoFMS admin, FileMaker XML structure) are also in `.claude/skills/`. Read them when you need API or XML details.

## Status

This repo is under construction. If a command named here doesn't exist yet, say so plainly instead of improvising a replacement, and point the consultant to the manual steps in `docs/consultant-guide.html`.
