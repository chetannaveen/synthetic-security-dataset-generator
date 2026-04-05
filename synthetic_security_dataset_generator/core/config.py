from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class GenerationConfig:
    dataset_name: str
    count: int = 100
    malicious_ratio: float = 0.35
    seed: int = 1337
    attack_types: list[str] = field(default_factory=list)
    output_dir: Path = Path("data/output")
    format: str = "json"

    def __post_init__(self) -> None:
        if self.count <= 0:
            raise ValueError("count must be positive")
        if not 0 <= self.malicious_ratio <= 1:
            raise ValueError("malicious_ratio must be between 0 and 1")
        if self.format not in {"json", "csv"}:
            raise ValueError("format must be 'json' or 'csv'")

    @property
    def suspicious_ratio(self) -> float:
        return 0.15 if self.dataset_name == "phishing" else 0.0
