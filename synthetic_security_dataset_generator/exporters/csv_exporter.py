from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.utils.record_utils import flatten_record


class CsvExporter:
    def export(
        self,
        records: list[dict[str, Any]],
        destination: Path,
        flatten_nested: bool = False,
        stream_write: bool = False,
        ml_format: bool = False,
    ) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        rows = [flatten_record(record, ml_format=ml_format) if (flatten_nested or ml_format) else record for record in records]
        fieldnames = self._collect_fields(rows)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: self._serialize(row.get(key)) for key in fieldnames})
        return destination

    def _collect_fields(self, records: list[dict[str, Any]]) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()
        for record in records:
            for key in record.keys():
                if key not in seen:
                    seen.add(key)
                    ordered.append(key)
        return ordered

    def _serialize(self, value: Any) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True)
        return "" if value is None else str(value)
