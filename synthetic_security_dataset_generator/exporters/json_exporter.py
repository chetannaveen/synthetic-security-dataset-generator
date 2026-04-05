from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonExporter:
    def export(self, records: list[dict[str, Any]], destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(records, indent=2), encoding="utf-8")
        return destination
