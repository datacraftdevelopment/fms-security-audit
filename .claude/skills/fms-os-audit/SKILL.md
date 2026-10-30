---
name: fms-os-audit
description: Guide the consultant through the read-only OS script pasted into a remote desktop session, then import its result. Use for the OS checklist.
---

# OS check

The consultant has only remote desktop access (RDP or Screen Sharing). No SSH, no WinRM, nothing installed.

1. Run `python -m audit.os-script win` or `... mac` (from `answers.yaml`). It copies the script to the consultant's clipboard.
2. Tell them:
   - **Windows:** in the RDP session, right-click Start, open Terminal (Admin) or PowerShell with Run as administrator, paste, press Enter.
   - **Mac:** in the Screen Sharing session, open Terminal, paste, press Return, and enter the admin password once when sudo asks.
3. The script prints a block between `----- FMS-AUDIT OS BEGIN v1 -----` and `----- FMS-AUDIT OS END -----` and copies it to the server's clipboard. Ask them to copy it back to their laptop (by hand if the clipboard doesn't sync).
4. Run `python -m audit.os-import --out audits/<slug>/<date>/os.json`. It reads the clipboard and verifies the checksum. If the checksum fails, the block was cut off; ask them to copy it again.
5. If they couldn't run as administrator, that's fine: admin-only checks show as Not checked. Mention it in the summary.
6. Remind them to close the terminal window on the server.

The scripts live in `scripts/`. They only read; never modify them to change settings.
