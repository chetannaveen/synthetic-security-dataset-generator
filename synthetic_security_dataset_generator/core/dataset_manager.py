from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.core.randomness_engine import RandomnessEngine


class DatasetManager:
    def __init__(self, config: GenerationConfig) -> None:
        self.config = config
        self.random = RandomnessEngine(config.seed)

    def split_dataset(self, records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        shuffled = list(records)
        self.random.shuffle(shuffled)
        total = len(shuffled)
        train_end = int(total * self.config.train_ratio)
        val_end = train_end + int(total * self.config.val_ratio)
        return {
            "train": shuffled[:train_end],
            "validation": shuffled[train_end:val_end],
            "test": shuffled[val_end:],
        }

    def write_split_files(
        self,
        splits: dict[str, list[dict[str, Any]]],
        exporter: Any,
        base_path: Path,
        fmt: str,
    ) -> dict[str, str]:
        outputs: dict[str, str] = {}
        for split_name, split_records in splits.items():
            path = base_path.parent / f"{base_path.stem}_{split_name}.{fmt}"
            exporter.export(split_records, path)
            outputs[split_name] = str(path)
        return outputs

    def create_manifest(
        self,
        dataset_name: str,
        records: list[dict[str, Any]],
        feature_list: list[str],
        outputs: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        labels = Counter(record.get("label", "unknown") for record in records)
        categories = Counter(record.get("category", "unknown") for record in records)
        manifest = {
            "dataset_name": dataset_name,
            "dataset_version": self.config.dataset_version,
            "record_count": len(records),
            "generation_config": {
                "count": self.config.count,
                "malicious_ratio": self.config.malicious_ratio,
                "seed": self.config.seed,
                "attack_types": self.config.attack_types,
                "format": self.config.format,
                "code_dataset_mode": self.config.code_dataset_mode,
            },
            "label_distribution": dict(labels),
            "category_distribution": dict(categories),
            "feature_list": feature_list,
            "outputs": outputs or {},
        }
        return manifest

    def write_manifest(self, manifest: dict[str, Any], destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return destination

    def summarize_dataset(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        manifest = self.create_manifest(
            dataset_name=self.config.dataset_name,
            records=records,
            feature_list=self.collect_feature_list(records),
        )
        return {
            "dataset_name": manifest["dataset_name"],
            "record_count": manifest["record_count"],
            "labels": manifest["label_distribution"],
            "categories": manifest["category_distribution"],
            "feature_count": len(manifest["feature_list"]),
        }

    def collect_feature_list(self, records: list[dict[str, Any]]) -> list[str]:
        features: set[str] = set()
        for record in records:
            features.update(record.get("features", {}).keys())
        return sorted(features)
