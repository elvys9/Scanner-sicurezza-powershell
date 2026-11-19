#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Converts the YAML catalog to JSON and validates it against schema.json.

Usage:
    python tools/yaml_to_json.py

Generates catalog/home_profile.json from catalog/home_profile.yaml.
Requires: pip install pyyaml jsonschema
"""

import json
import sys
import os

try:
    import yaml
except ImportError:
    print("ERROR: install PyYAML with 'pip install pyyaml'", file=sys.stderr)
    sys.exit(1)

try:
    import jsonschema
except ImportError:
    print("ERROR: install jsonschema with 'pip install jsonschema'", file=sys.stderr)
    sys.exit(1)


def main():
    # Paths relative to the project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)

    yaml_path = os.path.join(project_dir, "catalog", "home_profile.yaml")
    json_path = os.path.join(project_dir, "catalog", "home_profile.json")
    schema_path = os.path.join(project_dir, "catalog", "schema.json")

    # Load YAML
    print(f"Reading {yaml_path}...")
    with open(yaml_path, "r", encoding="utf-8") as f:
        catalog = yaml.safe_load(f)

    # Load schema
    print(f"Validating against {schema_path}...")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Validate
    jsonschema.validate(instance=catalog, schema=schema)

    # Check duplicate IDs
    ids = [c["id"] for c in catalog["controls"]]
    duplicates = [x for x in set(ids) if ids.count(x) > 1]
    if duplicates:
        print(f"ERROR: Duplicate IDs found: {duplicates}", file=sys.stderr)
        sys.exit(1)

    # Write JSON (UTF-8 without BOM, indented)
    print(f"Writing {json_path}...")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)
        f.write("\n")

    control_count = len(catalog["controls"])
    print(f"Done: {control_count} controls converted and validated.")


if __name__ == "__main__":
    main()
