---
name: pcap-analysis
description: When the user has a PCAP / PCAPNG file (CyberDefenders challenge, Malware-Traffic-Analysis sample, captured incident traffic) and needs to perform network forensics, use this skill. It walks the analyst through the four-stage SOP — Macro (NetworkMiner host overview), Micro (Wireshark display filters and TCP-stream reassembly), Artifact (CyberChef decoding), Sandbox (dynamic analysis of extracted binaries) — and produces an IOC table plus suggested Suricata/Sigma rules.
---

# PCAP Analysis — four-stage SOP

> **Privacy:** treat all extracted samples as live malware. Work inside an isolated VM with host-only networking. Default password for any zipped sample is `infected`.

## When to use this skill

- File path ends in `.pcap`, `.pcapng`, or `.cap`.
- User mentions Wireshark, tcpdump, NetworkMiner, Suricata, Zeek, JA3, SNI, or HTTP exfil.
- User is solving a network-forensics CyberDefenders / BTLO / THM SOC L1 room.

## Inputs

- Absolute path to a `.pcap[ng]` file.
- Optional: known time window, suspected victim IP, hypothesis.

## Workflow (four-stage SOP)

### Stage 1 — Macro analysis (NetworkMiner-style host overview)

Goal: get a one-screen mental map of who talked to whom.

If `scripts/pcap_preflight.py` is available, run:

```bash
python3 scripts/pcap_preflight.py <path-to-pcap> --json
```

This emits: capture window, top talkers by bytes, port distribution, protocol histogram, file count.

Manually flag anything matching:

- Meterpreter default port `4444`.
- SMB on `445` from a non-admin host.
- Outbound to non-RFC1918 on uncommon ports.
- DNS queries with high entropy / TXT records / unusually long FQDNs (possible DNS tunnel).
- TLS to IPs with no preceding DNS resolution.

Write findings into `findings.md` under **Timeline** with `confidence: low/medium`.

### Stage 2 — Micro filtering & stream reassembly (Wireshark)

For each suspicious host pair, generate the display filters the analyst should try in Wireshark. Always include at least:

```
ip.addr == <suspect> && tcp.port == <port>
http.request
dns.qry.name contains "<keyword>"
tls.handshake.extensions_server_name
```

Then instruct the analyst to **Follow TCP Stream** on the most suspicious flow and report back the first 40 lines.

### Stage 3 — Artifact extraction & decoding (CyberChef)

When the stream contains base64, gzip, XOR, or other encoded content:

1. Extract the encoded blob.
2. Propose a CyberChef recipe (URL or step list) — common starters:
   - `From Base64` → `Gunzip` → `Decode text(UTF-8)`
   - `From Base64` → `XOR (key: <hex>)` → `Decode text`
3. Identify whether the decoded content is a PowerShell loader, a config blob, or exfil data.
4. Add each decoded artefact and its decoded form to **IOCs**.

### Stage 4 — Sandbox & dynamic analysis

If Stage 3 produced an EXE / DLL / scripts:

1. Compute SHA-256 with `shasum -a 256 <file>`.
2. Recommend (do NOT auto-submit) checking VirusTotal / Hybrid Analysis / ANY.RUN.
3. If user has a local sandbox (FLARE-VM, Cuckoo, REMnux), suggest the parameters to capture: registry diff, child processes, C2 callouts.

## Outputs

Append to `findings.md`:

```markdown
## PCAP analysis — <pcap basename>

### Capture overview
- Window: <start> → <end> UTC
- Hosts: <n>; talkers (top 5): ...
- Protocols: ...

### Suspect flows
| Time | Src | Dst | Proto | Port | Note | Confidence |

### Decoded artefacts
| Stage | Original | Decoded | Confidence |

### IOCs
| Type | Value | Confidence | Source |

### MITRE ATT&CK
- T1071.001 — Application Layer Protocol: Web Protocols (if HTTP C2)
- T1071.004 — DNS C2 (if DNS tunnel)
- T1041 — Exfiltration over C2

### Suggested detections
- Suricata: <rule skeleton>
- Sigma: <rule skeleton or hand off to /detection-engineer>
```

## Hand-off

- IOCs → `/ioc-extractor` for normalisation.
- Decoded EXE/DLL → `@dfir-investigator` agent.
- Rule drafts → `/detection-engineer` for validation.
- Final write-up → `/ir-report`.

## Hard rules

- Never execute extracted samples from the PCAP on the analyst's main system.
- Mark TLS-only flows as `confidence: medium` unless JA3 / SNI corroborates.
- Do not infer attribution from IP geolocation alone.
