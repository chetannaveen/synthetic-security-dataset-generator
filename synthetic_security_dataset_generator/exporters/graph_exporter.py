from __future__ import annotations

import csv
from pathlib import Path


class GraphExporter:
    def export(self, edges: list[dict[str, str]], destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["src", "dst", "relation"])
            writer.writeheader()
            for edge in edges:
                writer.writerow(edge)
        return destination
