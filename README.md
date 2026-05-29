# Blue Team CTF — Skills & Agents for Claude Code

> **Language:** **English** · [繁體中文](README.zh-TW.md)

A complete Claude Code skill + subagent suite for defensive-security learning and competition: **AIS3 MyFirstCTF**, **金盾獎**, **HITCON Cyber Range**, **CyberDefenders**, **LetsDefend**, **BTLO**, **HTB Sherlocks**, and real SOC tier-1 / IR work.

Built from the integrated Blue Team CTF guide (`藍隊CTF完整指南-整合版.md`).

---

## What's inside

```
blueteam-ctf-project/
├── PRD.md                  Product requirements
├── SPEC.md                 Technical specification
├── claude-plugin.json      Plugin manifest
│
├── skills/                 7 skills (Markdown SKILL.md + templates)
│   ├── blueteam-triage/    entry-point router
│   ├── pcap-analysis/      four-stage network forensics SOP
│   ├── memory-forensics/   Volatility 3 playbook
│   ├── log-hunter/         Windows EVTX / Linux / SIEM hunting
│   ├── ioc-extractor/      regex IOC pulling + refang + redaction
│   ├── detection-engineer/ Sigma / YARA / Suricata authoring
│   └── ir-report/          BTL1-aligned 6-section report builder
│
├── agents/                 5 subagents
│   ├── soc-analyst.md      tier-1 alert triage
│   ├── dfir-investigator.md deep memory/disk/PCAP investigation
│   ├── threat-hunter.md    hypothesis-driven hunting
│   ├── detection-engineer.md rule lifecycle owner
│   └── ir-reporter.md      final report compiler + reviewer
│
├── scripts/                Python 3.10+, stdlib (optional scapy/yaml)
│   ├── extract_iocs.py     IOC extraction + refang + --redact mode
│   ├── pcap_preflight.py   PCAP macro-view summary
│   └── validate_sigma.py   Sigma 2.0 schema validation
│
├── templates/              IR report, Sigma, YARA, 5W note
├── examples/               sample IOC text + CTF walkthrough
└── docs/                   installation, privacy
```

## Quick start

### 1. Install as a plugin

```bash
cp -R blueteam-ctf-project ~/.claude/plugins/blueteam-ctf
```

Or run from anywhere:

```bash
git clone <this-repo> ~/blueteam-ctf-project
cd ~/blueteam-ctf-project
```

Skills auto-register from `skills/`; agents from `agents/`. Restart Claude Code if running.

### 2. Smoke test

```bash
python3 scripts/extract_iocs.py examples/sample-iocs.txt
python3 scripts/pcap_preflight.py --help
python3 scripts/validate_sigma.py templates/sigma-template.yml   # PASS-ish (placeholder UUID will fail; replace it)
```

### 3. Try a workflow

In Claude Code:

```
/blueteam-triage I just downloaded a PCAP from CyberDefenders called WebStrike.pcap
```

The triage skill will classify the artefact, set up `findings.md`, and route you to `/pcap-analysis`.

## Typical workflows

### A. Solo CTF challenge (CyberDefenders easy)

1. `/blueteam-triage <artefact>` — classify and set up notes.
2. `/pcap-analysis` or `/memory-forensics` or `/log-hunter` — deep-dive.
3. `/ioc-extractor` — consolidate IOCs.
4. `/detection-engineer` — write the Sigma rule (optional but portfolio gold).
5. `/ir-report` — produce the writeup. Publish to Medium / GitHub Pages.

### B. Production-style SOC simulation (LetsDefend / OpenSOC)

1. `@soc-analyst` — paste the alert, get a TP/FP verdict + 3 pivot queries.
2. Escalate → `@dfir-investigator` — deep memory + disk + log correlation.
3. `@threat-hunter` — hunt for spread to other hosts.
4. `@detection-engineer` — rules for every gap.
5. `@ir-reporter` — six-section report.

### C. Team competition (HITCON Cyber Range, golden-rotation)

Run agents in parallel against different artefacts; merge `findings.md` files; final pass through `@ir-reporter`.

## Privacy

This project assumes you may be looking at sensitive data. **Defaults err toward keeping data local.**

- Every skill carries a privacy reminder at the top.
- `scripts/extract_iocs.py --redact` replaces emails, IPs, and emits a local-only redaction map.
- For maximum privacy, run a local LLM (Ollama + Foundation-Sec-8B or WhiteRabbitNeo-V3) — see `docs/privacy.md`.

## Versioning

- v1.0 (this release): all skills, agents, scripts, templates, docs.
- v1.1: Mandarin SKILL.md mirrors, MCP server example (Splunk / CrowdStrike).
- v1.2: Docker compose for Security Onion + Wazuh.

See `PRD.md` §11 for full roadmap.

## Dependencies

- **Required:** Python 3.10+, Claude Code.
- **Optional:** PyYAML (for `validate_sigma.py`), scapy (for full `pcap_preflight.py`).

```bash
pip install pyyaml scapy
```

## Contributing

See `SPEC.md` for skill / agent / script conventions. PRs welcome.

## License

MIT. See `LICENSE`.

## Acknowledgements

Built on the integrated Blue Team CTF guide. References include:
TryHackMe SOC L1 / SAL1, LetsDefend, CyberDefenders, BTLO, HTB Sherlocks,
Security Blue Team BTL1, SANS DFIR, MITRE ATT&CK, SigmaHQ, SwiftOnSecurity,
The DFIR Report, 13Cubed, John Hammond, AIS3, HITCON.
