from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import csv


def flatten_record(record: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in record.items():
        flat_key = f"{prefix}{key}" if not prefix else f"{prefix}_{key}"
        if isinstance(value, dict):
            flattened.update(flatten_record(value, flat_key))
        elif isinstance(value, list):
            flattened[flat_key] = json.dumps(value, sort_keys=True)
        else:
            flattened[flat_key] = value
    return flattened


def load_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    raise ValueError(f"Unsupported dataset input format: {path.suffix}")
