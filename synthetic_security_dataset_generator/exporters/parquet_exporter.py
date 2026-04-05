from __future__ import annotations

from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.utils.record_utils import flatten_record


class ParquetExporter:
    def export(
        self,
        records: list[dict[str, Any]],
        destination: Path,
        flatten_nested: bool = False,
        stream_write: bool = False,
        ml_format: bool = False,
    ) -> Path:
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise RuntimeError("Parquet export requires optional dependency 'pyarrow'.") from exc

        destination.parent.mkdir(parents=True, exist_ok=True)
        rows = [flatten_record(record, ml_format=ml_format) if (flatten_nested or ml_format) else record for record in records]
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, destination)
        return destination
