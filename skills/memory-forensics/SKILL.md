---
name: memory-forensics
description: When the user has a memory image (.dmp, .mem, .raw, .vmem, lime) and needs to investigate it with Volatility 3 / MemProcFS / Rekall, use this skill. It produces an ordered playbook — image identification, process tree, network connections, injected code detection, credential extraction — with the exact Volatility 3 plugin names, expected output shape, and triage interpretation. Suitable for HTB Sherlocks, CyberDefenders memory challenges, and BTL1 prep.
---

# Memory Forensics — Volatility 3 playbook

> **Privacy:** memory images may contain credentials, session tokens, and PII for live users. Treat as sensitive data classification.

## When to use this skill

- File path ends in `.dmp`, `.mem`, `.raw`, `.vmem`, `.lime`, `.aff4`.
- User mentions Volatility, MemProcFS, Rekall, WinDbg, "memory dump", "memory image", "memory acquisition".
- User is solving a HTB Sherlocks / CyberDefenders memory / 13Cubed challenge.

## Inputs

- Absolute path to the memory image.
- Optional: known OS/version, suspected malware family, time of acquisition.

## Workflow

### Step 1 — Image identification

```bash
vol -f <image> windows.info        # Windows
vol -f <image> linux.banners       # Linux
vol -f <image> mac.mac_version     # macOS (if symbol pack present)
```

Capture: OS, build, kernel base, profile. Without a correct profile, every downstream plugin lies — re-confirm before proceeding.

### Step 2 — Process tree

```bash
vol -f <image> windows.pstree
vol -f <image> windows.psscan       # cross-check for hidden processes
```

Flag any of:

- Parent/child mismatches (e.g., `winword.exe` → `powershell.exe`).
- Processes with no parent in `pstree` but present in `psscan` → potential rootkit / unlinking.
- Unsigned binaries in `\Users\…\AppData\Local\Temp\`.
- Suspicious command lines via `windows.cmdline`.

### Step 3 — Network connections

```bash
vol -f <image> windows.netscan
vol -f <image> windows.netstat
```

Cross-reference foreign IPs against any IOCs already in `findings.md`. Note: NetScan reports historical sockets including closed ones.

### Step 4 — Injected code & DLL anomalies

```bash
vol -f <image> windows.malfind
vol -f <image> windows.dlllist --pid <suspect>
vol -f <image> windows.ldrmodules --pid <suspect>
```

`malfind` flags RWX private memory regions — usually injection. Dump with `--dump` for sandbox / disassembly hand-off.

### Step 5 — Credential extraction (where authorised)

```bash
vol -f <image> windows.hashdump
vol -f <image> windows.lsadump
vol -f <image> windows.cachedump
```

Only run when user confirms authorisation. Output goes to **IOCs** with `type: credential`, never echoed verbatim into a remote LLM context.

### Step 6 — Persistence indicators

```bash
vol -f <image> windows.registry.userassist
vol -f <image> windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f <image> windows.svcscan
```

### Step 7 — Timeline assembly

```bash
vol -f <image> timeliner --plugins=windows.pstree,windows.netscan,windows.registry.userassist
```

## Outputs

Append to `findings.md`:

```markdown
## Memory forensics — <image basename>

### Image profile
- OS / build / kernel base
- Acquisition time

### Process anomalies
| PID | PPID | Image | Reason flagged | Confidence |

### Network artefacts
| PID | Proto | Local | Foreign | State | Confidence |

### Injected regions
| PID | Address | Size | Protection | Dump file | Confidence |

### Persistence
| Mechanism | Key/Service | Value | Confidence |

### IOCs
| Type | Value | Confidence | Source |

### MITRE ATT&CK
- T1055 — Process Injection
- T1003 — OS Credential Dumping (if lsass touched)
- T1547.001 — Registry Run Keys
```

## Hand-off

- Dumped binaries → `@dfir-investigator` agent for reversing.
- New IOCs → `/ioc-extractor`.
- Persistence keys → `/detection-engineer` for Sigma rules.

## Hard rules

- Always identify the image profile before trusting other plugin output.
- Do not invent Volatility plugin names; if unsure, mark `confidence: low` and ask the user to verify with `vol --help`.
- Credential material is never echoed in narrative text — only inside the IOC table.
