# Example walkthrough — solving a CyberDefenders "WebStrike"-style PCAP

This is a synthetic walkthrough showing the full skill + agent flow on a
network-forensics challenge. Use as a model for your own writeups.

## Setup

Assume you have:

- `WebStrike.pcap` in `~/cases/webstrike/`
- Claude Code with `blueteam-ctf` plugin installed
- Python 3.10+ with `pip install scapy pyyaml`

## Turn 1 — triage

You:

```
/blueteam-triage I have ~/cases/webstrike/WebStrike.pcap from CyberDefenders
```

Expected response:

- Skill classifies as **network capture**.
- Creates `~/cases/webstrike/findings.md` with the 5W skeleton.
- Routes to `/pcap-analysis`.

## Turn 2 — Stage 1 macro

You:

```
/pcap-analysis
```

The skill runs (or asks you to run):

```bash
python3 ~/blueteam-ctf-project/scripts/pcap_preflight.py \
        ~/cases/webstrike/WebStrike.pcap --json
```

Output (synthetic):

```json
{
  "packet_count": 8421,
  "time_window_utc": [1715772721.10, 1715774982.55],
  "top_talkers": [["10.10.20.5", 4123], ["185.220.101.42", 2199], ...],
  "top_ports": [{"proto": "tcp", "port": 443, "count": 5012}, ...]
}
```

Skill flags `185.220.101.42` (non-RFC1918 to an internal host) as a Stage 1
suspect, with `confidence: medium`.

## Turn 3 — Stage 2 micro

The skill produces Wireshark display filters:

```
ip.addr == 185.220.101.42 && tcp.port == 443
tls.handshake.extensions_server_name
http.request
```

You open Wireshark, run them, and paste back the first interesting flow.

## Turn 4 — Stage 3 decode

Stream contained a base64 blob. You paste it. Skill proposes the CyberChef
recipe `From Base64 → Gunzip → Decode text(UTF-8)` and identifies the result
as a PowerShell stage-two loader.

## Turn 5 — IOCs

```
/ioc-extractor
```

Skill pulls the IPs, domains, and hashes out of the extracted strings into a
table. Writes to `findings.md` under `## IOCs`.

## Turn 6 — Detection rule

```
/detection-engineer write a Sigma rule for the encoded PS pattern we saw
```

Agent generates the rule, runs `validate_sigma.py`, writes to
`~/cases/webstrike/rules/sigma/encoded-ps-from-c2.yml`, and notes
Atomic Red Team test `T1059.001-3` for re-validation.

## Turn 7 — Report

```
@ir-reporter
```

Reads `findings.md` and produces `report-webstrike-2026-05-29.md` with all
six sections, peer-reviewed against the checklist. The agent's summary tells
you sections present, IOC count, and confidence distribution.

## What to publish

- `report-webstrike-2026-05-29.md` → your blog / Medium / GitHub Pages.
- `rules/sigma/encoded-ps-from-c2.yml` → contribute to your team / SigmaHQ.
- `findings.md` stays local (internal evidence chain).
