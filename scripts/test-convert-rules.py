#!/usr/bin/env python3
"""Round-trip tests for convert-rules.py.

Builds a temporary YAML ruleset (including single quotes, backslashes and
multiline regexes), converts it to gitleaks TOML / trufflehogv2 JSON /
trufflehogv3 YAML, parses each output back with its real parser and checks
that rule names and regexes survive unchanged. Also verifies that invalid
input exits non-zero. No network access required.
"""
import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

import yaml

SCRIPT = Path(__file__).resolve().parent / "convert-rules.py"
REPO_ROOT = Path(__file__).resolve().parent.parent

NASTY_RULES = {
    "patterns": [
        {"pattern": {
            "name": "Single 'quoted' Token",
            "regex": r"['\"]token['\"]\s*[:=]\s*['\"][A-Za-z0-9]{16}['\"]",
            "confidence": "high"}},
        {"pattern": {
            "name": "Backslash Path",
            "regex": r"C:\\Users\\[a-z]+\\secret\.txt",
            "confidence": "high"}},
        {"pattern": {
            "name": "Multiline Block",
            "regex": "-----BEGIN KEY-----\\n[A-Za-z0-9+/=]+\n-----END KEY-----",
            "confidence": "high"}},
        {"pattern": {
            "name": "Triple ''' quote ''' and \\ backslash \\",
            "regex": "'''\\\\d{4}'''",
            "confidence": "high"}},
        {"pattern": {
            "name": "Tab\tand \"double\" quotes",
            "regex": "key\\t=\\t\"[0-9a-f]{32}\"",
            "confidence": "high"}},
        {"pattern": {
            "name": "Low Confidence Skip",
            "regex": "low-[0-9]+",
            "confidence": "low"}},
    ]
}

INVALID_CASES = {
    "not-yaml": "patterns: [unclosed",
    "no-patterns-key": "foo: bar\n",
    "patterns-not-list": "patterns: {}\n",
    "missing-pattern": "patterns:\n  - name: x\n",
    "missing-regex": "patterns:\n  - pattern: {name: x, confidence: high}\n",
    "empty-name": "patterns:\n  - pattern: {name: '', regex: a+, confidence: high}\n",
    "bad-confidence": "patterns:\n  - pattern: {name: x, regex: a+, confidence: medium}\n",
    "invalid-regex": "patterns:\n  - pattern: {name: x, regex: '[unclosed', confidence: high}\n",
}


def run_converter(db_path, output_type, export_base=None):
    cmd = [sys.executable, str(SCRIPT), "--db", str(db_path),
           "--type", output_type]
    if export_base is not None:
        cmd += ["--export", str(export_base)]
    return subprocess.run(cmd, capture_output=True, text=True)


def high_confidence_map(rules_doc):
    return {p["pattern"]["name"]: p["pattern"]["regex"]
            for p in rules_doc["patterns"]
            if p["pattern"]["confidence"] == "high"}


def all_rules_map(rules_doc):
    return {p["pattern"]["name"]: p["pattern"]["regex"]
            for p in rules_doc["patterns"]}


def check_roundtrip(rules_doc, label):
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "rules.yml"
        db_path.write_text(yaml.safe_dump(rules_doc), encoding="utf-8")

        r = run_converter(db_path, "gitleaks", Path(tmp) / "out-gitleaks")
        if r.returncode != 0:
            failures.append(f"[{label}] gitleaks export failed: {r.stderr}")
        else:
            try:
                parsed = tomllib.loads(
                    (Path(tmp) / "out-gitleaks.toml").read_text(encoding="utf-8"))
                got = {rule["id"]: rule["regex"]
                       for rule in parsed.get("rules", [])}
                if got != high_confidence_map(rules_doc):
                    failures.append(f"[{label}] gitleaks drift: {got!r}")
            except tomllib.TOMLDecodeError as e:
                failures.append(f"[{label}] gitleaks TOML unparsable: {e}")

        r = run_converter(db_path, "trufflehogv2", Path(tmp) / "out-th2")
        if r.returncode != 0:
            failures.append(f"[{label}] trufflehogv2 export failed: {r.stderr}")
        else:
            try:
                got = json.loads(
                    (Path(tmp) / "out-th2.json").read_text(encoding="utf-8"))
                if got != high_confidence_map(rules_doc):
                    failures.append(f"[{label}] trufflehogv2 drift: {got!r}")
            except json.JSONDecodeError as e:
                failures.append(f"[{label}] trufflehogv2 JSON unparsable: {e}")

        r = run_converter(db_path, "trufflehogv3", Path(tmp) / "out-th3")
        if r.returncode != 0:
            failures.append(f"[{label}] trufflehogv3 export failed: {r.stderr}")
        else:
            try:
                parsed = yaml.safe_load(
                    (Path(tmp) / "out-th3.yml").read_text(encoding="utf-8"))
                detectors = parsed["detectors"]
                got = {}
                for d in detectors:
                    if set(d) != {"name", "keywords", "regex"}:
                        failures.append(
                            f"[{label}] trufflehogv3 unstable schema: {sorted(d)}")
                        break
                    if list(d["regex"]) != [d["name"]]:
                        failures.append(
                            f"[{label}] trufflehogv3 regex key != name: {d['name']!r}")
                        break
                    got[d["name"]] = d["regex"][d["name"]]
                else:
                    if got != all_rules_map(rules_doc):
                        failures.append(f"[{label}] trufflehogv3 drift: {got!r}")
            except (yaml.YAMLError, TypeError, KeyError) as e:
                failures.append(f"[{label}] trufflehogv3 YAML unparsable: {e}")
    return failures


def check_invalid_inputs():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for label, content in INVALID_CASES.items():
            db_path = Path(tmp) / f"bad-{label}.yml"
            db_path.write_text(content, encoding="utf-8")
            for output_type in ("gitleaks", "trufflehogv2", "trufflehogv3"):
                r = run_converter(db_path, output_type)
                if r.returncode == 0:
                    failures.append(
                        f"invalid input {label!r} accepted for {output_type}")
    return failures


def main():
    failures = []
    failures += check_roundtrip(NASTY_RULES, "nasty")
    failures += check_roundtrip({"patterns": []}, "empty")

    real_db = REPO_ROOT / "db" / "rules-stable.yml"
    with open(real_db, encoding="utf-8") as f:
        failures += check_roundtrip(yaml.safe_load(f), "rules-stable.yml")

    failures += check_invalid_inputs()

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("All convert-rules round-trip tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
