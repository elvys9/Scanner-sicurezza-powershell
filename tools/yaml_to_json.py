#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Converte il catalogo YAML in JSON e lo valida con schema.json.

Uso:
    python tools/yaml_to_json.py

Genera catalog/home_profile.json a partire da catalog/home_profile.yaml.
Richiede: pip install pyyaml jsonschema
"""

import json
import sys
import os

try:
    import yaml
except ImportError:
    print("ERRORE: installa PyYAML con 'pip install pyyaml'", file=sys.stderr)
    sys.exit(1)

try:
    import jsonschema
except ImportError:
    print("ERRORE: installa jsonschema con 'pip install jsonschema'", file=sys.stderr)
    sys.exit(1)


def main():
    # Percorsi relativi alla root del progetto
    dir_script = os.path.dirname(os.path.abspath(__file__))
    dir_progetto = os.path.dirname(dir_script)

    percorso_yaml = os.path.join(dir_progetto, "catalog", "home_profile.yaml")
    percorso_json = os.path.join(dir_progetto, "catalog", "home_profile.json")
    percorso_schema = os.path.join(dir_progetto, "catalog", "schema.json")

    # Carica YAML
    print(f"Lettura di {percorso_yaml}...")
    with open(percorso_yaml, "r", encoding="utf-8") as f:
        catalogo = yaml.safe_load(f)

    # Carica schema
    print(f"Validazione con {percorso_schema}...")
    with open(percorso_schema, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Valida
    jsonschema.validate(instance=catalogo, schema=schema)

    # Controlla ID duplicati
    ids = [c["id"] for c in catalogo["controls"]]
    duplicati = [x for x in set(ids) if ids.count(x) > 1]
    if duplicati:
        print(f"ERRORE: ID duplicati: {duplicati}", file=sys.stderr)
        sys.exit(1)

    # Scrivi JSON (UTF-8 senza BOM, indentato)
    print(f"Scrittura di {percorso_json}...")
    with open(percorso_json, "w", encoding="utf-8") as f:
        json.dump(catalogo, f, ensure_ascii=False, indent=2)
        f.write("\n")

    n_controlli = len(catalogo["controls"])
    print(f"Fatto: {n_controlli} controlli convertiti e validati.")


if __name__ == "__main__":
    main()
