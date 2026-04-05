from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import csv


def flatten_record(record: dict[str, Any], prefix: str = "", ml_format: bool = False) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in record.items():
        flat_key = f"{prefix}{key}" if not prefix else f"{prefix}_{key}"
        if isinstance(value, dict):
            flattened.update(flatten_record(value, flat_key, ml_format=ml_format))
        elif isinstance(value, list):
            if ml_format:
                flattened[flat_key] = float(len(value))
            else:
                flattened[flat_key] = json.dumps(value, sort_keys=True)
        elif ml_format and isinstance(value, bool):
            flattened[flat_key] = float(value)
        elif ml_format and value is None:
            flattened[flat_key] = 0.0
        elif ml_format and not isinstance(value, (int, float, str)):
            flattened[flat_key] = str(value)
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
