from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.utils.record_utils import flatten_record


class JsonExporter:
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
        if stream_write:
            with destination.open("w", encoding="utf-8") as handle:
                handle.write("[\n")
                for index, row in enumerate(rows):
                    if index:
                        handle.write(",\n")
                    handle.write(json.dumps(row))
                handle.write("\n]")
        else:
            destination.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return destination
