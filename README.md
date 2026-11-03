# FileMaker Security Audit

A best-practice security audit for a FileMaker Server and the files it hosts. You run it from your own laptop with Claude Code or Codex, and it produces a dated report for the client in three parts:

1. **Server checklist:** FileMaker Server and OttoFMS settings, read through their APIs.
2. **Operating system checklist:** firewall, open ports, patching, admins, disk encryption and antivirus, read by one script you paste into a remote desktop session.
3. **File audit:** accounts, privilege sets and extended privileges in every hosted file, read from a Save as XML export.

Nothing is installed on the server and nothing on it is changed.

**[Consultant guide](docs/consultant-guide.html)** · **[Sample report](docs/sample-report.html)** (fictitious client) · **[The checks in plain language](checklists/best-practices.md)**

> **Status: version 0.1.** It is tested end to end on fictitious data, and the XML parser is tested against a real FileMaker 26 export. It has not yet been run against a live client server. Until it has, some checks may show as Not checked where a server returns data in a shape the collector doesn't expect. That is safe: the report never guesses.

---

## Contents

- [What it checks](#what-it-checks)
- [What it does not do](#what-it-does-not-do)
- [Before you start](#before-you-start)
- [Install](#install)
- [Run an audit with Claude Code or Codex](#run-an-audit-with-claude-code-or-codex)
- [Run an audit by hand](#run-an-audit-by-hand)
- [Reading the report](#reading-the-report)
- [Re-audits and drift](#re-audits-and-drift)
- [Keeping client data safe](#keeping-client-data-safe)
- [Troubleshooting](#troubleshooting)
- [Repo layout](#repo-layout)
- [Changing the checks](#changing-the-checks)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## What it checks

There are 27 checks, each with a fixed ID so findings can be compared between audits. The full list with thresholds is in [checklists/best-practices.md](checklists/best-practices.md).

| Area | Examples | Read from |
| --- | --- | --- |
| Server (SRV-01 to 09) | FileMaker Server version, SSL certificate trust and expiry, encryption at rest, hosting only password-protected files, web technologies (Data API, OData, WebDirect, XML, PHP), backup schedules, script schedules running as Full Access, plug-ins, OttoFMS licence and API key expiry | FileMaker Admin API and OttoFMS API over HTTPS |
| Operating system (OS-01 to 09) | Unexpected listening ports and the program behind each, remote access services, firewall state and broad allow rules, OS version, patching, local administrators, disk encryption, antivirus, antivirus exclusions for the FileMaker data folders | One read-only script pasted into PowerShell or Terminal |
| Files (FIL-01 to 09) | Too many Full Access accounts, default account names, Guest access, everyone sharing one privilege set, wide privilege sets, export and print on restricted sets, extended privileges such as the Data API and OData, shared logins, external authentication | Save as XML export of each file |

Each check comes out as **Pass**, **Warn**, **Fail** or **Not checked**. The rules in `rules/` and `audit/rules.py` decide that, the same way every time. The AI agent only guides you and writes the executive summary.

## What it does not do

- Monitor the server over time or alert on changes.
- Read or review server logs.
- Test or crack passwords, or check password policy.
- Scan or probe the server from outside the network, or do penetration testing.
- Install anything on the server or change any setting.

## Before you start

**On your laptop**

| You need | Check with |
| --- | --- |
| Python 3.10 or later | `python3 --version` (Mac) or `python --version` (Windows) |
| Git | `git --version` |
| Claude Code or Codex (recommended) | [Claude Code](https://claude.com/claude-code) · [Codex](https://openai.com/codex/) |
| FileMaker Pro, to export the XML | Any version that has File > Save a Copy as XML |

**From the client**

| You need | Used for |
| --- | --- |
| Network reach to the server (office network or VPN). If the Admin Console opens in your browser, you have it | Server checks |
| A FileMaker Server Admin Console username and password. OttoFMS accepts the same login | Server and OttoFMS checks |
| Remote desktop access to the server (RDP for Windows, Screen Sharing for Mac), ideally as an administrator | OS checks |
| A Full Access login to each hosted file, or someone at the client who can export the XML for you | File checks |

Missing one of these doesn't stop the audit. The checks that depend on it show as Not checked, and the report says why.

## Install

```bash
git clone https://github.com/datacraftdevelopment/fms-security-audit.git
cd fms-security-audit
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest                 # optional: confirms everything works
```

For PDF reports, also run:

```bash
pip install playwright
python -m playwright install chromium
```

Without Playwright you still get the HTML report, which you can print to PDF from any browser.

Optionally, install the secret-scanning hook so a credential can never be committed by accident:

```bash
pip install pre-commit && pre-commit install
```

## Run an audit with Claude Code or Codex

This is the easy way. Open the repo folder in Claude Code (`claude`) or Codex (`codex`) and ask:

> **What do I do?**

The agent walks you through the whole audit one step at a time: it checks you have what you need, creates the audit folder, asks a few questions about the client, collects the server settings, gives you the OS script to paste, explains the XML export, and builds the report. The instructions it follows are in [AGENTS.md](AGENTS.md) (Codex reads it directly, and [CLAUDE.md](CLAUDE.md) points Claude Code to it). The skills it uses are in `.claude/skills/`.

Two things the agent will never do, and you shouldn't either:

- **Type passwords into the chat.** When it's time to log in, the agent asks you to open a *separate* terminal and run `python -m audit login <host>`. The password goes into your computer's keychain, not the conversation.
- **Hand-edit results.** If a finding looks wrong, the input or the rule needs fixing, not the report.

## Run an audit by hand

Everything the agent does is a plain command, so you can run an audit without an AI tool. The example uses a client called Example Co and a server at `fms.example.com`.

### 1. Create the audit folder

```bash
python -m audit new "Example Co" --server fms.example.com
# creates audits/example-co/2026-10-30/
```

Open `audits/example-co/2026-10-30/answers.yaml` and fill it in:

| Field | What to put |
| --- | --- |
| `platform` | `windows` or `mac` |
| `consultant`, `firm` | Who did the audit |
| `ottofms_installed` | `true` or `false` |
| `developer_accounts` | Accounts that legitimately need Full Access (your firm's, the client's IT lead) |
| `data_api_sets`, `odata_sets`, `webdirect_sets` | Privilege sets that are *supposed* to have that access. Any other set with it is flagged |
| `export_denied_sets` | Sets that should not be able to export or print |
| `summary` | The executive summary for the client, written last |

### 2. Store the server credentials

In your own terminal, not through an AI tool:

```bash
python -m audit login fms.example.com
python -m audit check-connection fms.example.com
```

Add `--otto` to `login` only if OttoFMS uses a different login from the Admin Console.

### 3. Collect server settings

```bash
python -m audit collect server fms.example.com --out audits/example-co/2026-10-30/
python -m audit collect otto   fms.example.com --out audits/example-co/2026-10-30/   # if OttoFMS is installed
```

These use only GET requests (plus the Admin API login and logout); the HTTP layer refuses anything else. If the server's certificate isn't trusted, the command stops, because that is itself a finding. With the client's agreement, re-run with `--allow-untrusted-cert`.

### 4. Run the OS check

```bash
python -m audit os-script win    # or: mac
```

The script is now on your clipboard. In your remote desktop session:

- **Windows:** right-click Start, open Terminal (Admin) or PowerShell as administrator, paste, press Enter.
- **Mac:** open Terminal, paste, press Return, and enter the admin password once when asked.

It only reads. It prints a block between `----- FMS-AUDIT OS BEGIN v1 -----` and `----- FMS-AUDIT OS END -----` and copies it to the server's clipboard. Copy that block back to your laptop, then:

```bash
python -m audit os-import --out audits/example-co/2026-10-30/
```

The block carries a checksum, so a block that was cut off while copying is rejected rather than half-read. If you couldn't run as administrator, the admin-only items show as Not checked.

### 5. Export each file's XML

For each hosted file, in FileMaker Pro, signed in with a Full Access account:

1. Choose **File > Save a Copy as XML**.
2. Save it as `<FileName>.xml` into `audits/example-co/2026-10-30/xml/`.

Then:

```bash
python -m audit parse-xml audits/example-co/2026-10-30/
```

This reads the accounts, privilege sets and extended privileges into `files.json`, and then **deletes the XML files**, because a Save as XML export can contain encrypted password hashes. Add `--keep-xml` only if you need the files for debugging.

### 6. Build the report

Write the `summary` in `answers.yaml`, then:

```bash
python -m audit report audits/example-co/2026-10-30/ --pdf
```

You get `findings.json`, `report.html` and `report.pdf` in the audit folder.

### 7. Close out

```bash
python -m audit logout fms.example.com
```

Deliver the PDF, move the audit folder to your firm's secure client storage, and ask the client to change the Admin Console password they lent you.

## Reading the report

The report runs in this order: cover, executive summary with the Pass/Warn/Fail tally, scope and method, server checklist, OS checklist, one section per file, a remediation plan with Fails first, an appendix (every account by file, installed plug-ins), and finally the disclaimer.

- **Fail:** fix this. It is a real exposure, such as an expired certificate, Guest access to data, or a file without encryption at rest.
- **Warn:** review it. It is often fine with a reason, such as an extra Full Access account or a key that never expires.
- **Not checked:** the data wasn't available. The finding says why.

See [the sample report](docs/sample-report.html) for a full example.

## Re-audits and drift

The most common problem after a server is handed over is drift: privileges creep open and everyone ends up on Full Access. To see what changed since last time, point the report at the previous audit:

```bash
python -m audit report audits/example-co/2027-04-30/ --previous audits/example-co/2026-10-30/ --pdf
```

Each finding is marked new or unchanged, and a "Fixed since last audit" list shows what was resolved.

## Keeping client data safe

- **Passwords** are typed only at the local `login` prompt and stored in the OS keychain (macOS Keychain or Windows Credential Manager). They never appear in files, the repo or the AI conversation. If one ends up in a chat, have the client change it.
- **Client data** lives only under `audits/`, which git ignores except for the template. Never commit it, attach it to an issue, or paste it into a pull request.
- **XML exports** can contain password hashes. They are deleted after parsing, and git ignores `*.xml` outside `samples/` and `tests/fixtures/`. Anything placed in `tests/fixtures/` must be scrubbed first.
- **Read-only by design:** the HTTP session blocks every request except GET, plus the Admin API login and logout, and a test checks that. The OS scripts only read.
- **AI processing:** account names and server settings pass through the AI tool you use. Make sure that fits your agreement with the client.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| `No stored credentials for <host>` | Run `python -m audit login <host>` in your own terminal. The host must match exactly. |
| Admin API login failed (401) | Wrong Admin Console credentials, or the account is locked. Check in a browser at `https://<host>/admin-console`. |
| Certificate not trusted | That's a finding (SRV-02). Re-run with `--allow-untrusted-cert` if the client agrees. |
| Many server checks show Not checked | The server returned fields the collector doesn't recognise yet. Look at `server_raw.json` in the audit folder and open an issue describing the field names (never attach the file). |
| OttoFMS did not answer | It probably isn't installed. Set `ottofms_installed: false`. |
| `os-import` says the checksum doesn't match | The block was cut off while copying. Copy it again from `BEGIN` to `END`. If the clipboard doesn't sync over remote desktop, save the block to a text file and use `--file`. |
| `parse-xml` finds no accounts | Make sure you used Save a Copy as XML (not a Database Design Report) and opened the file with a Full Access account. |
| No PDF | Install Playwright (see [Install](#install)), or open `report.html` in a browser and print to PDF. |

## Repo layout

```
fms-security-audit/
├── README.md                you are here
├── AGENTS.md                instructions for Codex and Claude Code
├── CLAUDE.md                Claude Code entry point (imports AGENTS.md)
├── .claude/skills/          audit skills, plus reference skills for the FileMaker Admin API, OttoFMS and Save as XML
├── audit/                   the Python package: collectors, XML parser, rules, report
├── rules/                   check definitions, thresholds and remediation text
├── checklists/              the checks in plain language
├── scripts/                 read-only OS scripts (Windows and Mac) and the sample builder
├── docs/                    consultant guide and sample report
├── samples/example-co/      fictitious inputs for the tests and the sample report
├── tests/                   tests; tests/fixtures/ holds a scrubbed real FileMaker 26 export
└── audits/                  your client work (git-ignored)
    ├── _template/           copied for each new audit
    └── <client>/<date>/
        ├── answers.yaml
        ├── server.json, otto.json, os.json, files.json
        ├── xml/             drop the Save as XML exports here
        └── findings.json, report.html, report.pdf
```

## Changing the checks

- **Thresholds and remediation text** are in `rules/server.yaml`, `rules/os.yaml` and `rules/files.yaml`. For example, the minimum FileMaker Server version is `min_version` under SRV-01, and the most Full Access accounts allowed is `max_full_access` under FIL-01.
- **Check logic** is in `audit/rules.py`, one function per check ID.
- **Bump `RULESET_VERSION`** in `audit/__init__.py` when you change a check, so reports show which standard they were run against.
- After a change, run `python scripts/build_sample.py` to regenerate the sample report, then `python -m pytest`.

Keep the minimum FileMaker Server version current with Claris's published security updates.

## Disclaimer

This tool produces a point-in-time review against the checks listed. It is not continuous monitoring, and a clean report does not guarantee that a system is secure. The client remains responsible for its servers, files and remediation. Every client report ends with this disclaimer, and it must not be removed or shortened.

## License

MIT, the same as RCC's [rcc-fm](https://github.com/FMTrainingTV-AI/rcc-fm) plugin. See [LICENSE](LICENSE). The reference skills in `.claude/skills/*-reference` are copied from rcc-fm.
