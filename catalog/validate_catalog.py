#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Valida il catalogo home_profile.yaml contro schema.json."""

import json
import sys
import os

try:
    import jsonschema
except ImportError:
    print("ERRORE: installa jsonschema con 'pip install jsonschema'", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("ERRORE: installa PyYAML con 'pip install pyyaml'", file=sys.stderr)
    sys.exit(1)


def valida_catalogo(percorso_yaml, percorso_schema):
    """Carica il catalogo YAML e lo valida contro lo schema JSON."""
    with open(percorso_yaml, "r", encoding="utf-8") as f:
        catalogo = yaml.safe_load(f)

    with open(percorso_schema, "r", encoding="utf-8") as f:
        schema = json.load(f)

    jsonschema.validate(instance=catalogo, schema=schema)
    return catalogo


def controlla_id_duplicati(catalogo):
    """Verifica che non ci siano ID duplicati nel catalogo."""
    ids = [c["id"] for c in catalogo["controls"]]
    duplicati = [x for x in ids if ids.count(x) > 1]
    if duplicati:
        raise ValueError(f"ID duplicati nel catalogo: {set(duplicati)}")


def main():
    dir_catalogo = os.path.dirname(os.path.abspath(__file__))
    # Lo script si trova in tools/, il catalogo in catalog/
    dir_progetto = os.path.dirname(dir_catalogo)
    percorso_yaml = os.path.join(dir_progetto, "catalog", "home_profile.yaml")
    percorso_schema = os.path.join(dir_progetto, "catalog", "schema.json")

    print(f"Validazione di {percorso_yaml}...")

    catalogo = valida_catalogo(percorso_yaml, percorso_schema)
    controlla_id_duplicati(catalogo)

    n_controlli = len(catalogo["controls"])
    print(f"Validazione superata: {n_controlli} controlli trovati.")


if __name__ == "__main__":
    main()
