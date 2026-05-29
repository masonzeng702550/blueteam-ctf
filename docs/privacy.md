# Privacy

This project is designed for handling potentially sensitive data — incident
logs, malware samples, internal hostnames, user account names, customer
identifiers. The defaults err toward keeping that data local.

## Threat model

The most common privacy failure for blue-team analysts is:

> "I'll just paste this log line into ChatGPT to ask what it means."

…which sends PII, internal asset names, and sometimes credentials to a third-
party model that may retain the data for training. In some jurisdictions
(EU GDPR, Taiwan PDPA, US sectoral laws) this is a reportable incident in its
own right.

## Built-in mitigations

### 1. Skill-level reminders

Every skill SKILL.md begins with a privacy reminder pointing the user at:

- `scripts/extract_iocs.py --redact` for offline scrubbing.
- The option to use a local LLM (Ollama + Foundation-Sec-8B / WhiteRabbitNeo-V3).

### 2. `extract_iocs.py --redact`

Replaces IPv4, IPv6, and email addresses with placeholders. Saves the
mapping to a sidecar JSON file that stays on disk — never sent to a model:

```bash
python3 scripts/extract_iocs.py incident-ticket.txt \
        --redact --redact-map ./redactions.json > ticket-safe.txt
```

The output `ticket-safe.txt` is safe to share with a hosted model.

### 3. Agent hard rules

`@soc-analyst` refuses to echo full passwords, tokens, credit cards, or
PII even if present in the input.

### 4. No network calls in v1.0

No script in this release calls VirusTotal, AbuseIPDB, or any other API.
Any enrichment happens because YOU explicitly run a tool, not because the
agent did it behind your back.

## Recommended local-LLM stack

If you process sensitive data regularly, run a local model:

```bash
# Install Ollama
brew install ollama          # macOS
# or curl -fsSL https://ollama.com/install.sh | sh

# Pull a security-tuned model
ollama pull foundation-sec-8b      # Cisco Foundation AI
# or
ollama pull whiterabbitneo-v3      # cyber LLM

# Wire to Claude Code via OpenAI-compatible endpoint
# (Open WebUI provides one; see Ollama docs)
```

Then point this project's prompts at the local endpoint. The skills are
prompt-only — no telemetry to remote services.

## What you still must do

- **Acquire data legally.** This project does not validate authorisation.
- **Maintain chain of custody.** Use hashes; do not modify originals; record
  acquisition method in `findings.md`.
- **Set retention.** `findings.md`, `hunts.md`, `report-*.md`, and
  `redactions.json` may contain sensitive data. Delete or archive per your
  data retention policy.
- **Classify reports.** Use TLP markings in `report-*.md` (the template
  defaults to TLP:AMBER).

## When in doubt

Refuse to process and ask the data owner. The same discipline an analyst
would apply to ediscovery applies to LLM input.
