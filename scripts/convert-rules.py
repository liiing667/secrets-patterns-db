#!/usr/bin/env python3
import sys
import json
import yaml
import argparse
import re


class InvalidDatabaseError(ValueError):
    pass


def load_database(path):
    try:
        with open(path, "r") as f:
            y = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise InvalidDatabaseError(f"cannot read/parse database file: {e}")

    if not isinstance(y, dict) or not isinstance(y.get("patterns"), list):
        raise InvalidDatabaseError(
            "database must be a mapping with a 'patterns' list")

    rules = []
    for idx, entry in enumerate(y["patterns"]):
        where = f"patterns[{idx}]"
        if not isinstance(entry, dict) or not isinstance(
                entry.get("pattern"), dict):
            raise InvalidDatabaseError(f"{where}: missing 'pattern' mapping")
        p = entry["pattern"]
        name = p.get("name")
        regex = p.get("regex")
        confidence = p.get("confidence")
        if not isinstance(name, str) or not name.strip():
            raise InvalidDatabaseError(f"{where}: 'name' must be a non-empty string")
        if not isinstance(regex, str) or not regex:
            raise InvalidDatabaseError(
                f"{where} ({name!r}): 'regex' must be a non-empty string")
        if confidence not in ("low", "high"):
            raise InvalidDatabaseError(
                f"{where} ({name!r}): 'confidence' must be 'low' or 'high'")
        try:
            re.compile(regex)
        except re.error as e:
            raise InvalidDatabaseError(
                f"{where} ({name!r}): invalid regex: {e}")
        rules.append({"name": name, "regex": regex, "confidence": confidence})
    return rules


def toml_basic_string(value):
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def trufflehogv2_output(rules):
    output = {}
    for r in rules:
        if r["confidence"] != "high":
            continue
        output[r["name"]] = r["regex"]
    return json.dumps(output, indent=4, sort_keys=True)


def trufflehogv3_output(rules):
    detectors = []
    for r in rules:
        keywords = [k for k in re.split(r"[.,;:?!_\-\s]+", r["name"]) if k]
        detectors.append({
            "name": r["name"],
            "keywords": keywords,
            "regex": {r["name"]: r["regex"]},
        })
    return yaml.safe_dump({"detectors": detectors}, sort_keys=False,
                          default_flow_style=False, allow_unicode=True)


def gitleaks_output(rules):
    lines = ['title = "gitleaks config"']
    for r in rules:
        if r["confidence"] != "high":
            continue
        lines.append("[[rules]]")
        lines.append(f"    id = {toml_basic_string(r['name'])}")
        lines.append(f"    description = {toml_basic_string(r['name'])}")
        lines.append(f"    regex = {toml_basic_string(r['regex'])}")
        lines.append('    keywords = ["secret"]')
    return "\n".join(lines) + "\n"


OUTPUT_TYPES = {
    "trufflehogv2": ("json", trufflehogv2_output),
    "trufflehogv3": ("yml", trufflehogv3_output),
    "gitleaks": ("toml", gitleaks_output),
}


def main(arg):
    try:
        rules = load_database(arg.database_file)
    except InvalidDatabaseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    ext_string, render = OUTPUT_TYPES[arg.output_type]
    output_string = render(rules)

    if arg.export_filename is not None:
        with open(f"{arg.export_filename}.{ext_string}", "w") as f:
            f.write(output_string)
    else:
        print(output_string, end="")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert yaml database file to rules for trufflehogv2, trufflehogv3 or gitleaks")
    parser.add_argument("--db", dest="database_file", required=True,
                        help="The yaml database file")
    parser.add_argument("--type", dest="output_type", required=True,
                        choices=sorted(OUTPUT_TYPES),
                        help="Supported output types: trufflehogv2, trufflehogv3, gitleaks")
    parser.add_argument("--export", dest="export_filename",
                        help="Give filename, extension toml/json/yml will be added")
    args = parser.parse_args()

    sys.exit(main(args))
