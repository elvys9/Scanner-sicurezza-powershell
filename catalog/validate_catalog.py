#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validates the home_profile.yaml catalog against schema.json."""

import json
import sys
import os

try:
    import jsonschema
except ImportError:
    print("ERROR: install jsonschema with 'pip install jsonschema'", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("ERROR: install PyYAML with 'pip install pyyaml'", file=sys.stderr)
    sys.exit(1)


def validate_catalog(yaml_path, schema_path):
    """Loads the YAML catalog and validates it against the JSON schema."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        catalog = yaml.safe_load(f)

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    jsonschema.validate(instance=catalog, schema=schema)
    return catalog


def check_duplicate_ids(catalog):
    """Verifies that there are no duplicate control IDs in the catalog."""
    ids = [c["id"] for c in catalog["controls"]]
    duplicates = [x for x in ids if ids.count(x) > 1]
    if duplicates:
        raise ValueError(f"Duplicate IDs in catalog: {set(duplicates)}")


def main():
    catalog_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(catalog_dir)
    yaml_path = os.path.join(project_dir, "catalog", "home_profile.yaml")
    schema_path = os.path.join(project_dir, "catalog", "schema.json")

    print(f"Validating {yaml_path}...")

    catalog = validate_catalog(yaml_path, schema_path)
    check_duplicate_ids(catalog)

    control_count = len(catalog["controls"])
    print(f"Validation passed: {control_count} controls found.")


if __name__ == "__main__":
    main()
