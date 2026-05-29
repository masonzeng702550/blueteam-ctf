#!/usr/bin/env python3
"""
extract_iocs.py — Extract, refang, dedupe, and optionally redact IOCs from text.

Stdlib-only. Reads from a file path or stdin (use "-").

Usage:
    python3 extract_iocs.py input.txt
    cat input.txt | python3 extract_iocs.py -
    python3 extract_iocs.py input.txt --json
    python3 extract_iocs.py input.txt --redact --redact-map redactions.json

Exit codes:
    0 success
    1 user error (bad args, missing file)
    2 internal error

Doctest:
    >>> _refang("hxxp://1.2.3[.]4/evil")
    'http://1.2.3.4/evil'
    >>> _refang("example[.]com")
    'example.com'
    >>> sorted(extract("see 8.8.8.8 and evil[.]com and SHA256 "
    ...                 + "a"*64).keys())
    ['domain', 'ipv4', 'sha256']
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# --- Regex catalogue ----------------------------------------------------------

PATTERNS = {
    "ipv4":    re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
                          r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
    "ipv6":    re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.I),
    "domain":  re.compile(r"\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}"
                          r"[a-z0-9])?\.){1,}[a-z]{2,24}\b", re.I),
    "url":     re.compile(r"\bhttps?://[^\s<>\"']+", re.I),
    "email":   re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "md5":     re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha1":    re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "sha256":  re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "cve":     re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "mitre":   re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "btc":     re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
}

PRIVATE_IPV4 = re.compile(
    r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.|"
    r"22[4-9]\.|23\d\.|255\.)"
)

VENDOR_NOISE_DOMAINS = {
    "microsoft.com", "google.com", "github.com", "cloudflare.com",
    "amazon.com", "apple.com", "windows.com", "live.com",
    "googleapis.com", "gstatic.com", "akamai.net",
}

# --- Refang -------------------------------------------------------------------

REFANG_RULES = [
    (re.compile(r"h\s*[xX]\s*[xX]\s*p", re.I), "http"),
    (re.compile(r"h\s*[xX]\s*[xX]\s*ps", re.I), "https"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[:]"), ":"),
    (re.compile(r"\[@\]"), "@"),
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\[at\]", re.I), "@"),
]


def _refang(text: str) -> str:
    for pat, rep in REFANG_RULES:
        text = pat.sub(rep, text)
    return text


# --- Extraction ---------------------------------------------------------------

def extract(text: str) -> dict[str, list[str]]:
    """Return {type: [unique values...]} for IOCs found in `text`.

    Public ipv4 only; vendor-noise domains stripped; case-normalised hashes.
    """
    text = _refang(text)
    found: dict[str, list[str]] = {}

    for kind, pat in PATTERNS.items():
        raw = pat.findall(text)
        if not raw:
            continue
        normalised = []
        seen = set()
        for v in raw:
            v_norm = v.lower() if kind in {"md5", "sha1", "sha256",
                                            "domain", "email", "url"} else v
            if kind == "ipv4" and PRIVATE_IPV4.match(v_norm):
                continue
            if kind == "domain" and v_norm in VENDOR_NOISE_DOMAINS:
                continue
            if v_norm in seen:
                continue
            seen.add(v_norm)
            normalised.append(v_norm)
        if normalised:
            found[kind] = normalised
    return found


# --- Redaction ----------------------------------------------------------------

REDACT_TARGETS = ("ipv4", "ipv6", "email")
REDACT_PLACEHOLDER = {
    "ipv4":  "[REDACTED-IPV4-{n}]",
    "ipv6":  "[REDACTED-IPV6-{n}]",
    "email": "[REDACTED-EMAIL-{n}]",
}


def redact(text: str) -> tuple[str, dict]:
    """Replace sensitive IOCs with placeholders; return (redacted_text, map)."""
    text = _refang(text)
    mapping: dict[str, dict[str, str]] = {k: {} for k in REDACT_TARGETS}
    for kind in REDACT_TARGETS:
        pat = PATTERNS[kind]
        counter = {"n": 0}

        def _replace(m: re.Match) -> str:
            value = m.group(0)
            if kind == "ipv4" and PRIVATE_IPV4.match(value):
                return value
            if value in mapping[kind]:
                return mapping[kind][value]
            counter["n"] += 1
            placeholder = REDACT_PLACEHOLDER[kind].format(n=counter["n"])
            mapping[kind][value] = placeholder
            return placeholder

        text = pat.sub(_replace, text)
    return text, mapping


# --- CLI ----------------------------------------------------------------------

def _render_markdown(found: dict[str, list[str]]) -> str:
    if not found:
        return "_No IOCs found._\n"
    lines = ["| Type | Value | Count-in-extraction |",
             "|------|-------|---------------------|"]
    for kind in sorted(found):
        for value in found[kind]:
            lines.append(f"| {kind} | `{value}` | 1 |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", help="Path to input file, or - for stdin")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    p.add_argument("--redact", action="store_true",
                   help="Print redacted text to stdout (overrides --json/Markdown)")
    p.add_argument("--redact-map", metavar="FILE",
                   help="Write redaction map JSON to FILE (sensitive; keep local)")
    p.add_argument("--dry-run", action="store_true",
                   help="Parse input, report sizes, do not emit IOC values")
    args = p.parse_args(argv)

    try:
        if args.input == "-":
            data = sys.stdin.read()
        else:
            path = Path(args.input)
            if not path.exists():
                print(f"error: file not found: {path}", file=sys.stderr)
                return 1
            data = path.read_text(errors="replace")
    except OSError as e:
        print(f"error reading input: {e}", file=sys.stderr)
        return 2

    if args.dry_run:
        found = extract(data)
        counts = {k: len(v) for k, v in found.items()}
        print(json.dumps({"chars": len(data), "ioc_counts": counts}, indent=2))
        return 0

    if args.redact:
        redacted, mapping = redact(data)
        sys.stdout.write(redacted)
        if args.redact_map:
            try:
                Path(args.redact_map).write_text(json.dumps(mapping, indent=2))
            except OSError as e:
                print(f"warning: could not write redact map: {e}", file=sys.stderr)
        else:
            print("\n# Redaction map (also rerun with --redact-map to save):",
                  file=sys.stderr)
            print(json.dumps(mapping, indent=2), file=sys.stderr)
        return 0

    found = extract(data)
    if args.json:
        print(json.dumps(found, indent=2, sort_keys=True))
    else:
        print(_render_markdown(found))
    return 0


if __name__ == "__main__":
    sys.exit(main())
