# Windows Event ID cheatsheet for blue-team triage

Source aggregations: MITRE ATT&CK, Microsoft docs, SANS DFIR cheatsheets.

## Security log — authentication & logon

| Event ID | Meaning | Why blue team cares |
|----------|---------|---------------------|
| 4624 | Successful logon | Logon type tells you HOW (2=interactive, 3=network, 4=batch, 5=service, 7=unlock, 10=RDP, 11=cached) |
| 4625 | Failed logon | Brute force, password spray, mistyped passwords |
| 4634 | Logoff | Pair with 4624 to compute session duration |
| 4648 | Explicit credentials used | RunAs, lateral movement with alt creds |
| 4672 | Special privileges assigned | Admin logon — should be rare on user hosts |
| 4720 | User account created | Persistence indicator |
| 4732 | Member added to local group | Privilege escalation (esp. local Administrators) |

## Security log — Kerberos

| Event ID | Meaning |
|----------|---------|
| 4768 | TGT requested |
| 4769 | Service ticket requested |
| 4770 | TGT renewed |
| 4771 | Pre-auth failed |
| 4776 | NTLM authentication attempt on DC |

Hunt patterns:
- 4769 with `Ticket Encryption Type: 0x17` (RC4) on a modern domain → possible Kerberoasting.
- 4768 with unusual lifetime / encryption mismatch → Golden Ticket.
- 4776 from non-domain accounts spike → NTLM relay / brute force.

## System log

| Event ID | Meaning |
|----------|---------|
| 7045 | Service installed |
| 7036 | Service state changed |
| 6005 / 6006 | Event log started / stopped |
| 104 | Log cleared (HIGH severity flag) |

## Sysmon (Operational channel)

| Event ID | Meaning | Hunt example |
|----------|---------|--------------|
| 1 | Process create | Parent/child anomaly, encoded PowerShell |
| 3 | Network connection | Rare process making outbound |
| 7 | Image loaded | Suspicious DLL into lsass |
| 8 | CreateRemoteThread | Process injection |
| 10 | ProcessAccess | LSASS access from non-system |
| 11 | File create | Drop in startup/Temp |
| 13 | Registry value set | Run keys |
| 22 | DNS query | Unusual TLDs, DGA |

## Task scheduler

| Event ID | Meaning |
|----------|---------|
| 4698 | Scheduled task created |
| 4702 | Scheduled task updated |
| 106 | (TaskScheduler/Operational) Task registered |

## PowerShell

| Event ID | Source | Meaning |
|----------|--------|---------|
| 4103 | PowerShell/Operational | Module logging |
| 4104 | PowerShell/Operational | Script block logging — primary hunt source |
| 400 / 600 | PowerShell (legacy) | Engine state changed |

## Application log selections

| Event ID | Source | Meaning |
|----------|--------|---------|
| 1000 | Application Error | Process crash — sometimes exploit aftermath |
| 1116 / 1117 | Microsoft-Windows-Windows Defender | Malware detected / action taken |

## RDP-specific

| Event ID | Channel | Meaning |
|----------|---------|---------|
| 1149 | TerminalServices-RemoteConnectionManager/Operational | RDP user authentication succeeded |
| 21 | TerminalServices-LocalSessionManager/Operational | Session logon succeeded |
| 24 | same | Session disconnected |

## Defender / AMSI

| Event ID | Channel | Meaning |
|----------|---------|---------|
| 1116 | Defender | Malware detected |
| 5007 | Defender | Configuration changed (possible tamper) |
