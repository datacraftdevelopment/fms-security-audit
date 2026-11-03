# FileMaker best-practice checklist

The plain-language standard the rules in `rules/` implement. Every check returns Pass, Warn, Fail or Not checked. Thresholds are defaults and can be changed per audit.

## Server (Admin API)

| ID | Check | Fails or warns when |
| --- | --- | --- |
| SRV-01 | FileMaker Server version | Below the minimum safe version for known vulnerabilities |
| SRV-02 | SSL certificate | Default Claris certificate, expired, or expiring within 30 days |
| SRV-03 | Encryption at rest | Any hosted file not encrypted |
| SRV-04 | Host password-protected files only | Setting is off |
| SRV-05 | Web technologies | Data API, OData, WebDirect, XML or PHP on without a stated need |
| SRV-06 | Backup schedules | No enabled backup schedule, or last run failed |
| SRV-07 | Script schedules | Warn on schedules run by a Full Access account; Not checked when the API doesn't say which account runs them |
| SRV-08 | Plug-ins | Listed for review |
| SRV-09 | OttoFMS | Invalid licence, API keys with no expiry, or expired keys still listed |

## Operating system (pasted script)

| ID | Check | Fails or warns when |
| --- | --- | --- |
| OS-01 | Listening ports | Any port not on the expected list |
| OS-02 | Remote access services | RDP, SSH, SMB, VNC, TeamViewer or AnyDesk listening |
| OS-03 | Firewall | Any profile off (fail); broad allow rules for non-FileMaker ports (warn) |
| OS-04 | OS version | Past end of support, or unsupported by the installed FMS version |
| OS-05 | Patching | Nothing installed in 45 days, or automatic updates off |
| OS-06 | Local administrators | Generic or shared admin accounts |
| OS-07 | Disk encryption | Volume with FileMaker data or backups not encrypted |
| OS-08 | Antivirus | None running, or signatures older than 7 days |
| OS-09 | Antivirus exclusions | Live database folder scanned in real time (Claris recommends excluding it); Windows only, and only when Microsoft Defender is the active antivirus |

## Files (accounts-only XML)

| ID | Check | Fails or warns when |
| --- | --- | --- |
| FIL-01 | Full Access accounts | More than 2, or any used day to day by staff |
| FIL-02 | Default account names | An active account named Admin or similar |
| FIL-03 | Guest account | Enabled |
| FIL-04 | Everyone on one privilege set | Over 80% of active accounts share a set with broad modify or delete rights |
| FIL-05 | Wide privilege sets | Non-developer sets that can modify layouts, scripts or value lists, or manage accounts |
| FIL-06 | Export and print | Allowed where the client said it should not be; Not checked when the client named no sets |
| FIL-07 | Extended privileges | fmrest, fmodata, fmwebdirect or fmxml on sets that don't need them |
| FIL-08 | Shared logins | One account connected from several machines at audit time |
| FIL-09 | External authentication | Listed; group membership must be reviewed in the directory |

## Out of scope

Passwords and password policy, ongoing monitoring, log review, and any testing from outside the network.
