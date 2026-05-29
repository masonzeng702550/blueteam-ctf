# SPEC — Blue Team CTF Skill & Agent Suite

**Companion to:** `PRD.md`
**Version:** 1.0
**Audience:** developers contributing skills, agents, or scripts to this project.

---

## 1. Architecture overview

```
┌─────────────────────────────────────────────────────────────┐
│                        User (analyst)                       │
└───────────────────────────┬─────────────────────────────────┘
                            │ invokes /skill-name OR @agent
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                       Claude Code                           │
│                                                             │
│   ┌──────────────┐    ┌──────────────┐   ┌──────────────┐   │
│   │   Skills     │    │   Agents     │   │   Scripts    │   │
│   │ (SKILL.md +  │◄──►│ (subagent    │──►│ (Python 3,   │   │
│   │  templates)  │    │  prompts)    │   │  stdlib)     │   │
│   └──────────────┘    └──────────────┘   └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                ┌─────────────────────────┐
                │  User's local artefacts │
                │  (PCAP, EVTX, mem dump) │
                └─────────────────────────┘
```

Three layers:

1. **Skills** are how the user *invokes a workflow* (verbs: triage, hunt, report).
2. **Agents** are how the user *delegates a role* (nouns: SOC analyst, DFIR investigator).
3. **Scripts** are deterministic helpers the agents may call when an exact, reproducible transformation is needed (e.g., regex IOC extraction).

A skill may instruct the model to spawn an agent; an agent may instruct the model to invoke a skill. There is no enforced hierarchy.

## 2. Repository layout

```
blueteam-ctf-project/
├── README.md
├── PRD.md
├── SPEC.md
├── LICENSE
├── .gitignore
├── claude-plugin.json
│
├── skills/
│   ├── blueteam-triage/SKILL.md
│   ├── pcap-analysis/
│   │   ├── SKILL.md
│   │   └── scripts/pcap_preflight.py     # symlink to /scripts
│   ├── memory-forensics/SKILL.md
│   ├── log-hunter/
│   │   ├── SKILL.md
│   │   └── references/windows-event-ids.md
│   ├── ioc-extractor/
│   │   ├── SKILL.md
│   │   └── scripts/extract_iocs.py       # symlink to /scripts
│   ├── detection-engineer/
│   │   ├── SKILL.md
│   │   ├── scripts/validate_sigma.py     # symlink to /scripts
│   │   └── templates/
│   └── ir-report/
│       ├── SKILL.md
│       └── templates/ir-report-template.md
│
├── agents/
│   ├── soc-analyst.md
│   ├── dfir-investigator.md
│   ├── threat-hunter.md
│   ├── detection-engineer.md
│   └── ir-reporter.md
│
├── scripts/                       # canonical location; skills reference these
│   ├── extract_iocs.py
│   ├── pcap_preflight.py
│   └── validate_sigma.py
│
├── templates/
│   ├── ir-report.md
│   ├── sigma-template.yml
│   ├── yara-template.yar
│   └── 5w-note.md
│
├── examples/
│   ├── ctf-walkthrough.md
│   └── sample-iocs.txt
│
└── docs/
    ├── installation.md
    └── privacy.md
```

## 3. Skill specification

### 3.1 File format

Every `SKILL.md` MUST have YAML frontmatter:

```yaml
---
name: skill-name
description: When the user ... (concrete trigger). Use this skill to ...
---
```

- `name` — kebab-case, ≤30 chars, unique across the project.
- `description` — MUST begin with a trigger condition ("When the user provides …", "When the analyst needs to …"). Models score `description` against the user's turn; vague descriptions never fire. ≤200 words.

### 3.2 Body sections (recommended order)

1. **When to use this skill** — bullet list of trigger scenarios.
2. **Inputs** — what artefact / context the skill expects.
3. **Workflow** — numbered steps. For investigative skills, use the **four-stage SOP** structure (Macro → Micro → Artifact → Sandbox).
4. **Outputs** — what the user receives (Markdown sections, tables, file writes).
5. **Templates & references** — relative paths to files under `templates/` or `references/`.
6. **Hand-off** — which other skill or agent to chain into.
7. **Privacy** — one-line reminder.

### 3.3 Output contract

Every investigative skill MUST produce, at minimum:

```markdown
## Findings
- (bulleted findings with confidence levels: low/medium/high)

## IOCs
| Type | Value | Confidence | Source |
|------|-------|------------|--------|

## MITRE ATT&CK
- Txxxx.yyy — technique name

## Next steps
- (≤5 concrete actions)
```

### 3.4 Plugin manifest

`claude-plugin.json` at repo root:

```json
{
  "name": "blueteam-ctf",
  "version": "1.0.0",
  "description": "Blue Team CTF skills and agents",
  "skills": ["./skills"],
  "agents": ["./agents"]
}
```

Install: `cp -R blueteam-ctf-project ~/.claude/plugins/blueteam-ctf`.

## 4. Agent specification

### 4.1 File format

Agents live in `agents/<name>.md` with frontmatter:

```yaml
---
name: agent-name
description: Use this agent when ... PROACTIVELY use when ...
tools: Read, Write, Edit, Bash, Grep, Glob
model: sonnet
---
```

- `tools` — comma-separated allowlist. Default to read-only (`Read, Grep, Glob`) unless the agent must write rules/reports.
- `model` — `sonnet` for routine triage, `opus` for `dfir-investigator` and `threat-hunter`.

### 4.2 Body structure

1. **Role** — one-paragraph persona ("You are a senior SOC analyst with 7 years of DFIR experience…").
2. **Mandate** — bulleted responsibilities.
3. **Investigation workflow** — the steps the agent follows on each invocation.
4. **Output format** — exact Markdown skeleton.
5. **Escalation criteria** — when to hand off and to which agent.
6. **Hard rules** — no fabrication of CVEs/plugins; mark confidence; refuse offensive tasks.

### 4.3 Tool & execution policy

- Agents may run scripts under `scripts/`. They MUST pass `--dry-run` first if the script supports it.
- Agents MUST NOT execute commands that fetch external content unless the user has explicitly approved network access in that turn.
- Agents producing detection rules MUST chain through `validate_sigma.py` before delivering.

## 5. Script specification

All Python scripts:

- Target Python 3.10+.
- Use stdlib only unless explicitly declared; document optional deps in the module docstring.
- Provide `--help`, `--dry-run`, `--redact` flags where applicable.
- Exit codes: `0` success, `1` user error, `2` internal error.
- Write JSON to stdout when `--json` is passed; otherwise human-readable text.
- Never make network calls in v1.0.

## 6. Versioning & spec pins

- **Sigma spec:** v2.0 (2024-11).
- **MITRE ATT&CK:** v15.x (Enterprise).
- **Volatility:** 3.x plugin naming.
- **CompTIA Security+:** SY0-701.

When any of these versions bumps a major number, open an issue tagged `spec-bump`.

## 7. Testing

Each script ships with a docstring example block. Run `python3 -m doctest scripts/extract_iocs.py -v` to verify. CI (when added) will execute doctests + a smoke test of every SKILL.md being valid YAML.

## 8. Privacy & safety

- README's first post-install section is **Privacy**.
- `extract_iocs.py --redact` replaces detected emails, IPv4, and 8.3 filenames with `[REDACTED-EMAIL]` etc., emitting a sidecar `redaction-map.json` for the analyst to keep locally.
- All skills include the line: *"If the source data is sensitive, run `scripts/extract_iocs.py --redact` first or use a local LLM (Ollama + Foundation-Sec-8B)."*

## 9. Conventions

- Markdown headings: ATX style (`#`, `##`).
- Tables: GitHub-flavoured.
- Code fences: language-tagged.
- Time: UTC in all reports; analyst notes the local offset once at the top.
- File names: kebab-case for skills/agents; snake_case for Python.

## 10. Future work pointers

- §6.4 of source guide (MCP) → v1.1 will add `mcp/` directory with example `splunk-mcp` config.
- §7 of source guide (one-person blue team) → v1.2 will add `docker/security-onion-wazuh-compose.yml`.
- §6.8 of source guide (fine-tuning) → v2.0 LoRA recipe.
