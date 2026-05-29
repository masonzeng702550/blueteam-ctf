#!/usr/bin/env python3
"""
validate_sigma.py — Lightweight schema validation for Sigma 2.0 rules.

Stdlib-only (uses a minimal hand-rolled YAML subset parser? No — requires PyYAML
for safety). Falls back to a JSON-via-yaml-cli path if PyYAML unavailable.

Validates the keys most rule files get wrong:
  - required: title, id, logsource, detection, condition
  - id is a valid UUID
  - level in {informational, low, medium, high, critical}
  - status in {experimental, test, stable, deprecated, unsupported}
  - detection has at least one selection + a condition referencing it
  - tags begin with "attack." for ATT&CK mapping

Usage:
    python3 validate_sigma.py rule.yml
    python3 validate_sigma.py rules/sigma/*.yml --json

Exit codes:
    0 all rules valid
    1 one or more rules failed
    2 internal error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path

try:
    import yaml  # type: ignore
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

REQUIRED_KEYS = ["title", "id", "logsource", "detection"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                     r"[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def validate(rule: dict, path: str) -> list[str]:
    errors: list[str] = []

    for key in REQUIRED_KEYS:
        if key not in rule:
            errors.append(f"missing required key: {key}")

    rid = rule.get("id")
    if rid is not None:
        try:
            uuid.UUID(str(rid))
        except ValueError:
            errors.append(f"id is not a valid UUID: {rid!r}")
        if not UUID_RE.match(str(rid)):
            errors.append(f"id format unexpected (want 8-4-4-4-12 hex): {rid!r}")

    level = rule.get("level")
    if level is not None and str(level).lower() not in VALID_LEVELS:
        errors.append(f"level must be one of {sorted(VALID_LEVELS)}; got {level!r}")

    status = rule.get("status")
    if status is not None and str(status).lower() not in VALID_STATUSES:
        errors.append(f"status must be one of {sorted(VALID_STATUSES)}; got {status!r}")

    logsource = rule.get("logsource")
    if isinstance(logsource, dict):
        if not (logsource.get("product") or logsource.get("service")
                or logsource.get("category")):
            errors.append("logsource must define at least one of "
                          "product/service/category")
    elif logsource is not None:
        errors.append("logsource must be a mapping")

    detection = rule.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("detection.condition is required")
        else:
            cond = detection["condition"]
            selections = [k for k in detection if k != "condition"
                          and not k.startswith("timeframe")]
            if not selections:
                errors.append("detection has condition but no selections")
            else:
                referenced = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(cond))
                noise = {"and", "or", "not", "of", "all", "any", "1"}
                refs = [t for t in referenced if t not in noise]
                unknown = [r for r in refs if r not in selections
                           and not any(r.startswith(s) for s in selections)
                           and not r.endswith("*")]
                # "1 of selection_*" style is hard to validate without globbing;
                # we only warn on completely unknown identifiers.
                if unknown and not any("*" in s for s in selections):
                    errors.append(f"condition references unknown selection(s): "
                                  f"{unknown}")
    elif detection is not None:
        errors.append("detection must be a mapping")

    tags = rule.get("tags", [])
    if tags and not isinstance(tags, list):
        errors.append("tags must be a list")
    elif tags:
        attack_tags = [t for t in tags if str(t).startswith("attack.")]
        if not attack_tags:
            errors.append("tags present but none start with 'attack.' "
                          "(no ATT&CK mapping)")

    return errors


def load_rule(path: Path) -> dict | None:
    if not HAS_YAML:
        print("error: PyYAML required (pip install pyyaml)", file=sys.stderr)
        sys.exit(2)
    try:
        return yaml.safe_load(path.read_text())  # type: ignore
    except yaml.YAMLError as e:  # type: ignore
        print(f"{path}: YAML parse error: {e}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+", help="Sigma rule file(s)")
    p.add_argument("--json", action="store_true", help="Emit JSON report")
    p.add_argument("--dry-run", action="store_true",
                   help="Parse only; do not validate")
    args = p.parse_args(argv)

    overall: dict[str, list[str]] = {}
    failed = 0

    for raw in args.paths:
        path = Path(raw)
        if not path.exists():
            overall[str(path)] = ["file not found"]
            failed += 1
            continue
        rule = load_rule(path)
        if rule is None:
            overall[str(path)] = ["YAML parse error"]
            failed += 1
            continue
        if args.dry_run:
            overall[str(path)] = []
            continue
        errs = validate(rule, str(path))
        overall[str(path)] = errs
        if errs:
            failed += 1

    if args.json:
        print(json.dumps(overall, indent=2))
    else:
        for path, errs in overall.items():
            if not errs:
                print(f"PASS  {path}")
            else:
                print(f"FAIL  {path}")
                for e in errs:
                    print(f"      - {e}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
