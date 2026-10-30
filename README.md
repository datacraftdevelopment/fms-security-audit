# FileMaker Security Audit

A best-practice security audit for a FileMaker Server and the files it hosts, run by a consultant from their own laptop with Claude Code or Codex. You get a dated report with three parts: a server checklist, an operating system checklist, and an account and privilege audit for each file.

> **Status: under construction.** The guide, sample report and agent instructions are here. The audit code and scripts are being built. Commands in this README are the planned ones.

**[Read the consultant guide](docs/consultant-guide.html)** · **[See a sample report](docs/sample-report.html)** (fictitious client)

## What it checks

- **Server:** FileMaker Server version, SSL certificate, encryption at rest, web publishing (Data API, OData, WebDirect), backups, schedules, plug-ins, and OttoFMS if installed. Read through the FileMaker Admin API.
- **Operating system:** listening ports and the program behind each, firewall, OS version and patching, local administrators, disk encryption, antivirus. Read by one script you paste into a remote desktop session.
- **Files:** Full Access accounts, Guest access, default account names, wide privilege sets, extended privileges such as the Data API. Read from an accounts-only Save as XML export of each file.

What it does **not** do: monitor the server over time, review logs, test passwords, or scan the server from outside. Nothing is installed on the server.

## Quick start

1. **Install the tools on your laptop:** Python 3.10 or later, and either [Claude Code](https://claude.com/claude-code) or [Codex](https://openai.com/codex/).
2. **Get the repo:**
   ```
   git clone https://github.com/<owner>/fms-security-audit.git
   cd fms-security-audit
   pip install -r requirements.txt
   ```
3. **Open it in Claude Code or Codex and ask: "What do I do?"** The agent walks you through the audit one step at a time. You don't need any other FileMaker skills or plug-ins; they are included.

## What you'll need from the client

- Network access to the server (office network or VPN)
- FileMaker Server Admin Console credentials, and OttoFMS credentials if it's installed
- Remote desktop access to the server (RDP for Windows, Screen Sharing for Mac), ideally as an administrator
- A Full Access login for each file, or someone at the client to export the XML for you

## How a run works

1. The agent creates a folder for the audit under `audits/<client>/<date>/`.
2. You log in at a local prompt (`python -m audit.login <host>`). Passwords go to your computer's keychain, never into the chat.
3. The agent reads the server settings over HTTPS.
4. You paste one read-only script into PowerShell or Terminal in your remote desktop session and copy the result back.
5. You save an accounts-only XML of each file into the audit's `xml/` folder.
6. The agent runs the rules and builds the report as HTML and PDF.

## Repo layout

```
fms-security-audit/
├── README.md               you are here
├── AGENTS.md               instructions for Codex and Claude Code
├── CLAUDE.md               Claude Code entry point (imports AGENTS.md)
├── .claude/skills/         audit skills plus FileMaker reference skills
├── docs/                   consultant guide and sample report
├── audit/                  Python package: collectors, parser, rules engine, report
├── rules/                  rule definitions and thresholds
├── checklists/             the best-practice standard in plain language
├── scripts/                read-only OS scripts for Windows and Mac
├── samples/example-co/     fictitious inputs used for tests and the sample
├── tests/
└── audits/                 your client work (git-ignored)
    └── <client>/<date>/
        ├── xml/            put the Save as XML exports here
        ├── answers.yaml
        ├── findings.json
        └── report.html, report.pdf
```

## Keeping client data safe

- Passwords are typed only at a local prompt and stored in the OS keychain. Never paste one into the agent.
- Everything about a client lives under `audits/`, which git ignores. Don't commit it, and don't attach it to issues.
- A secret-scanning pre-commit hook blocks anything that looks like a credential.
- Account names and server settings are processed by the AI tool you use. Make sure that fits your client agreement.

## Disclaimer

This tool produces a point-in-time review against the checks listed. It is not continuous monitoring, and a clean report does not guarantee a system is secure. The client remains responsible for its servers, files and remediation.

## License

To be decided.
