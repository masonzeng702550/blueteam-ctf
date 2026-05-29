# Installation

## Option 1 — Claude Code plugin (recommended)

```bash
cp -R blueteam-ctf-project ~/.claude/plugins/blueteam-ctf
```

Restart Claude Code. The seven skills become invokable with `/<skill-name>`;
the five agents become invokable with `@<agent-name>` or via the `Agent`
tool's `subagent_type` parameter.

Verify:

```
/blueteam-triage what skills are available?
```

## Option 2 — Project-local

If you prefer per-project skills (e.g., a CTF write-up repo):

```bash
git clone <repo> .claude/blueteam-ctf
```

and add a `.claude/settings.json`:

```json
{
  "pluginPaths": [".claude/blueteam-ctf"]
}
```

## Option 3 — Run the scripts standalone

The Python scripts are useful even without Claude Code:

```bash
cd blueteam-ctf-project
python3 scripts/extract_iocs.py - < /var/log/auth.log
python3 scripts/pcap_preflight.py capture.pcap --json
python3 scripts/validate_sigma.py rules/sigma/*.yml
```

## Dependencies

| Tool | Required for | Install |
|------|--------------|---------|
| Python 3.10+ | all scripts | system |
| PyYAML | `validate_sigma.py` | `pip install pyyaml` |
| scapy | full `pcap_preflight.py` (talker / port histograms) | `pip install scapy` |
| jq | pretty-print `--json` outputs | system package manager |

No script in v1.0 makes network calls. Adding optional VirusTotal / GreyNoise
enrichment is on the v1.x roadmap.

## Updating

```bash
cd ~/.claude/plugins/blueteam-ctf
git pull
```

No data migration needed; user-generated `findings.md`, `hunts.md`, and
`report-*.md` files are gitignored.

## Uninstall

```bash
rm -rf ~/.claude/plugins/blueteam-ctf
```

User-generated outputs remain untouched in your case directories.
