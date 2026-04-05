from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class GenerationConfig:
    dataset_name: str
    count: int = 100
    malicious_ratio: float = 0.35
    seed: int = 1337
    attack_types: list[str] = field(default_factory=list)
    output_dir: Path = Path("data/output")
    format: str = "json"
    dataset_version: str = "v0.2.0"
    flatten_nested: bool = False
    stream_write: bool = False
    code_dataset_mode: str = "classification"
    train_ratio: float = 0.7
    val_ratio: float = 0.15
    test_ratio: float = 0.15
    chunk_size: int = 500
    ml_format: bool = False
    progress: bool = False
    schema_version: str = "2026.04"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.count <= 0:
            raise ValueError("count must be positive")
        if not 0 <= self.malicious_ratio <= 1:
            raise ValueError("malicious_ratio must be between 0 and 1")
        if self.format not in {"json", "csv", "parquet"}:
            raise ValueError("format must be 'json', 'csv', or 'parquet'")
        if self.code_dataset_mode not in {"classification", "localization"}:
            raise ValueError("code_dataset_mode must be 'classification' or 'localization'")
        if round(self.train_ratio + self.val_ratio + self.test_ratio, 6) != 1.0:
            raise ValueError("train/val/test ratios must sum to 1.0")
        if self.chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

    @property
    def suspicious_ratio(self) -> float:
        return 0.15 if self.dataset_name == "phishing" else 0.0
