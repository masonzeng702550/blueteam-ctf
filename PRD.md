# PRD — Blue Team CTF Skill & Agent Suite

**Document owner:** tjspsschool@gmail.com
**Version:** 1.0
**Last updated:** 2026-05-29
**Source material:** `藍隊CTF完整指南-整合版.md`

---

## 1. Background & Problem Statement

Defensive security learners — students preparing for AIS3 / 金盾獎 / HITCON Cyber Range, junior SOC analysts, and one-person blue teams in SMBs — repeatedly hit the same wall:

1. **Investigation paralysis.** Given a PCAP, EVTX, or memory dump, they do not know which tool to reach for first or in what order. The four-stage SOP (Macro → Micro → Artifact → Sandbox) exists in books but not in a runnable workflow.
2. **Inconsistent reports.** Writeups omit the Executive Summary, MITRE ATT&CK mapping, or IOC table that hiring managers and CTF judges actually grade on.
3. **AI is used as a chatbot, not a teammate.** Analysts paste a log into ChatGPT and get a paragraph back — they do not have repeatable prompt templates, do not enforce confidence levels, and have no privacy guardrails for sensitive logs.
4. **Detection engineering is intimidating.** Writing the first Sigma or YARA rule, then validating it against Atomic Red Team, has no on-ramp.

This project packages the methodology in the integrated Blue Team CTF guide as **Claude Code skills, subagents, helper scripts, and templates** — so the same prompt that an experienced DFIR analyst would issue becomes one Skill invocation away.

## 2. Goals

| # | Goal | Success measure |
|---|------|-----------------|
| G1 | Reduce time-to-first-finding on a new PCAP/EVTX/memory artefact from 30+ min to under 5 min | A new analyst, given a CyberDefenders easy challenge, reaches the first IOC in ≤5 min using the relevant skill |
| G2 | Produce IR reports that pass the BTL1 / SAL1 rubric on the first draft | Generated reports include all 6 sections (Exec Summary, Timeline, IOC table, ATT&CK mapping, Technical Analysis, Remediation) without prompting |
| G3 | Make detection engineering a 10-minute loop, not a multi-hour project | From "I saw this IOC" to "validated Sigma rule" in ≤10 min, including Atomic Red Team test mapping |
| G4 | Keep sensitive logs on-device by default | Skills explicitly warn before sending PII/sample data to remote APIs; scripts redact common PII patterns offline |
| G5 | Be installable as a Claude Code plugin and as a standalone reference | Single `cp -R` into `~/.claude/plugins/` activates all skills and agents |

## 3. Non-goals

- We do **not** ship malicious samples or live C2 infrastructure.
- We do **not** automate offensive actions; red-team artefacts appear only as test stimuli for Atomic Red Team / Caldera validation loops.
- We do **not** replace SANS / BTL1 / CCD coursework — this is a workflow accelerator, not a curriculum.
- We do **not** vendor-lock to a single SIEM; query templates exist for Splunk SPL, Elastic KQL, and Sentinel KQL.

## 4. Target users & personas

| Persona | Profile | Primary skills used |
|---------|---------|---------------------|
| **Mei, 大三資管 student** | Preparing AIS3 MyFirstCTF, no SOC experience | `blueteam-triage`, `pcap-analysis`, `ir-report` |
| **Junior SOC analyst (THM SAL1 holder)** | 6 months in a tier-1 queue, wants to graduate to detection engineering | `log-hunter`, `detection-engineer`, `threat-hunter` agent |
| **One-person blue team at a 50-person startup** | No SOC budget, owns Wazuh + Sysmon | `ioc-extractor`, `detection-engineer`, `ir-report`, all agents |
| **CTF team captain** | Coordinating 4 players across PCAP/memory/log tracks during HITCON Cyber Range | All five subagents in parallel |

## 5. Scope

### 5.1 In scope (v1.0)

**Seven skills**

1. `blueteam-triage` — entry-point router; classifies the artefact type and hands off to the right deep-dive skill.
2. `pcap-analysis` — four-stage SOP for network forensics (NetworkMiner → Wireshark → CyberChef → sandbox).
3. `memory-forensics` — Volatility 3 / MemProcFS investigation playbook.
4. `log-hunter` — Windows Event Log + Linux auth.log + IIS/Apache hunting, with SPL/KQL generation.
5. `ioc-extractor` — pull IPs, domains, hashes, emails, and defanged URLs out of any text/log/PCAP excerpt; deduplicate and enrich.
6. `detection-engineer` — author and validate Sigma + YARA + Suricata rules; map to Atomic Red Team tests.
7. `ir-report` — produce the 6-section IR report (Exec Summary, Timeline, IOC table, ATT&CK, Technical Analysis, Remediation) from accumulated findings.

**Five subagents** (in `agents/` for Claude Code subagent system)

- `soc-analyst` — Tier-1 alert triage and routing.
- `dfir-investigator` — Deep-dive memory/disk/PCAP investigation.
- `threat-hunter` — Proactive hypothesis-driven hunting.
- `detection-engineer` — Rule authoring and validation.
- `ir-reporter` — Final report compilation and review.

**Helper scripts** (Python 3.10+, stdlib-only where possible)

- `extract_iocs.py` — regex IOC extractor with defang/refang.
- `pcap_preflight.py` — capinfos-style summary using `scapy` if present, falls back to stdout headers.
- `validate_sigma.py` — schema-validate Sigma YAML against the official 2.0 spec.

**Templates**

- IR report (Markdown, BTL1-aligned).
- Sigma rule skeleton.
- YARA rule skeleton.
- 5W investigation note.

**Documentation**

- PRD (this file), SPEC, README with install + usage.

### 5.2 Out of scope (v1.0, may revisit in v1.x)

- A live MCP server bundling Splunk/Wazuh queries (the guide section 6.4 covers this — we ship the prompt templates but not the server itself).
- Docker compose for Security Onion / Wazuh stand-up.
- Mandarin localisation of skill descriptions (English-first per user decision; templates remain bilingual where the underlying guide is bilingual).
- Fine-tuned local LLM weights — we document the Ollama + Foundation-Sec-8B path but do not ship a model.

## 6. User stories

- **US-01** *As Mei*, when I download a `.pcap` from a CyberDefenders challenge, I invoke `/pcap-analysis` and get a checklist for the four-stage SOP, with the first three Wireshark display filters I should try.
- **US-02** *As a junior SOC analyst*, when an alert fires for "suspicious PowerShell on HR-LAPTOP", I invoke the `soc-analyst` agent with the raw Sysmon log; it returns a triage verdict, the next three pivot queries in SPL, and a draft escalation note.
- **US-03** *As a one-person blue team*, when I find a new C2 IP in my Suricata logs, I invoke `/detection-engineer` with the IP and the surrounding context and get a Sigma rule, a Snort rule, and the Atomic Red Team test ID that would re-validate the detection.
- **US-04** *As a CTF team captain*, I run the `dfir-investigator` and `threat-hunter` agents in parallel against memory and log artefacts respectively, and merge their findings via `/ir-report` for a single submission.
- **US-05** *As any user with sensitive data*, when I pass logs containing PII, the skill warns me and offers to run `extract_iocs.py --redact` locally first.

## 7. Constraints

- **Privacy default:** every skill that ingests log/PCAP content includes a top-of-file reminder: *"If this data is sensitive, redact PII first or use a local LLM."*
- **No hallucinated CVEs.** Skills instruct the agent to mark every CVE / Volatility plugin / KQL function reference with a confidence level (`low/medium/high`) and to refuse to invent identifiers.
- **Markdown-only outputs** by default (agents may produce JSON when explicitly asked).
- **No network calls** from helper scripts in v1.0 — every script runs offline.
- **License:** MIT for the project; user is responsible for verifying licences of any malware samples or PCAPs they analyse.

## 8. Assumptions

- User has Claude Code installed and at least one model available.
- User has Python 3.10+ for helper scripts.
- User understands that this project is **not** a substitute for legal authorisation when handling third-party data.

## 9. Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Skill descriptions are too generic and never trigger | Med | High | Each SKILL.md description starts with concrete triggers ("when the user provides a PCAP, EVTX...") and lists synonyms |
| Generated Sigma rules are syntactically wrong | Med | Med | `validate_sigma.py` runs on every generated rule before report inclusion |
| Users send PII to remote models despite warnings | Med | High | `ioc-extractor` ships with `--redact` mode; README has a privacy section as the first chapter after install |
| Project rots as MITRE ATT&CK / Sigma spec evolves | High over 12 months | Med | Version pin in SPEC §6; quarterly review issue in README backlog |

## 10. Success metrics (post-launch)

- Mei completes AIS3 MyFirstCTF 2026 with ≥1 challenge solved using only this toolkit.
- Three writeups published referencing this project within the first quarter.
- Zero issues filed about hallucinated CVE references in generated reports.

## 11. Release plan

- **v1.0 (this release):** all skills, agents, scripts, templates, docs.
- **v1.1:** add Mandarin SKILL.md mirrors; bundle MCP server example.
- **v1.2:** Docker compose for Security Onion + Wazuh lab.
- **v2.0:** fine-tuned LoRA on top of Foundation-Sec-8B with this project's prompt corpus.

## 12. Open questions

- Should agents call helper scripts directly (`Bash` tool), or only suggest commands for the analyst to run? — **Decision in SPEC §4.3:** they may execute, but only inside `scripts/` and only with `--dry-run` first by default.
- Do we ship a `claude-plugin.json` so the whole thing installs as a single plugin? — **Yes**, added in SPEC §3.4.
