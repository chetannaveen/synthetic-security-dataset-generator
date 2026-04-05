from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.core.randomness_engine import RandomnessEngine


class DatasetManager:
    def __init__(self, config: GenerationConfig) -> None:
        self.config = config
        self.random = RandomnessEngine(config.seed)

    def split_dataset(self, records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            key = (str(record.get("label", "unknown")), str(record.get("category", "unknown")))
            buckets[key].append(record)

        splits: dict[str, list[dict[str, Any]]] = {"train": [], "validation": [], "test": []}
        for bucket_records in buckets.values():
            shuffled = list(bucket_records)
            self.random.shuffle(shuffled)
            total = len(shuffled)
            train_end = int(total * self.config.train_ratio)
            val_end = train_end + int(total * self.config.val_ratio)
            splits["train"].extend(shuffled[:train_end])
            splits["validation"].extend(shuffled[train_end:val_end])
            splits["test"].extend(shuffled[val_end:])

        for split_records in splits.values():
            self.random.shuffle(split_records)
        return splits

    def analyze_split_imbalance(
        self,
        records: list[dict[str, Any]],
        splits: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        overall = self._distribution(records)
        split_distributions = {name: self._distribution(items) for name, items in splits.items()}
        imbalance_by_label: dict[str, float] = {}
        warnings: list[str] = []
        for label, overall_ratio in overall["labels"].items():
            deviations = []
            for split_name, split_stats in split_distributions.items():
                split_ratio = split_stats["labels"].get(label, 0.0)
                deviations.append(abs(split_ratio - overall_ratio))
                if overall_ratio > 0 and abs(split_ratio - overall_ratio) > 0.2:
                    warnings.append(f"high skew for label '{label}' in split '{split_name}'")
            imbalance_by_label[label] = round(max(deviations) if deviations else 0.0, 4)
        return {
            "overall_distribution": overall,
            "split_distributions": split_distributions,
            "imbalance_by_label": imbalance_by_label,
            "warnings": sorted(set(warnings)),
        }

    def write_split_files(
        self,
        splits: dict[str, list[dict[str, Any]]],
        exporter: Any,
        base_path: Path,
        fmt: str,
        flatten_nested: bool = False,
        ml_format: bool = False,
    ) -> dict[str, str]:
        outputs: dict[str, str] = {}
        for split_name, split_records in splits.items():
            path = base_path.parent / f"{base_path.stem}_{split_name}.{fmt}"
            exporter.export(split_records, path, flatten_nested=flatten_nested, ml_format=ml_format)
            outputs[split_name] = str(path)
        return outputs

    def create_manifest(
        self,
        dataset_name: str,
        records: list[dict[str, Any]],
        feature_list: list[str],
        outputs: dict[str, str] | None = None,
        split_analysis: dict[str, Any] | None = None,
        graph_outputs: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        labels = Counter(record.get("label", "unknown") for record in records)
        categories = Counter(record.get("category", "unknown") for record in records)
        manifest = {
            "dataset_name": dataset_name,
            "dataset_version": self.config.dataset_version,
            "schema_version": self.config.schema_version,
            "record_count": len(records),
            "generation_config": {
                "count": self.config.count,
                "malicious_ratio": self.config.malicious_ratio,
                "seed": self.config.seed,
                "attack_types": self.config.attack_types,
                "format": self.config.format,
                "code_dataset_mode": self.config.code_dataset_mode,
                "chunk_size": self.config.chunk_size,
                "ml_format": self.config.ml_format,
            },
            "label_distribution": dict(labels),
            "category_distribution": dict(categories),
            "feature_list": feature_list,
            "outputs": outputs or {},
            "split_analysis": split_analysis or {},
            "graph_outputs": graph_outputs or {},
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

    def extract_graph_edges(self, dataset_name: str, records: list[dict[str, Any]]) -> list[dict[str, str]]:
        edges: list[dict[str, str]] = []
        for record in records:
            if dataset_name == "phishing":
                url = record.get("url", "")
                campaign_id = record.get("metadata", {}).get("campaign_id")
                domain = record.get("metadata", {}).get("whois", {}).get("domain")
                if campaign_id and domain:
                    edges.append({"src": campaign_id, "dst": domain, "relation": "uses_domain"})
                if campaign_id and url:
                    edges.append({"src": campaign_id, "dst": url, "relation": "delivers_url"})
            elif dataset_name == "logs":
                campaign_id = record.get("campaign_id")
                session_id = record.get("session_id")
                for event in record.get("events", []):
                    if campaign_id:
                        edges.append({"src": campaign_id, "dst": event.get("ip", ""), "relation": "originates_from_ip"})
                    if session_id:
                        edges.append({"src": session_id, "dst": event.get("user", "unknown"), "relation": "observed_user"})
            elif dataset_name == "user_behavior":
                user_id = record.get("user_id")
                for event in record.get("events", []):
                    edges.append({"src": user_id, "dst": event.get("ip", ""), "relation": "uses_ip"})
                    edges.append({"src": user_id, "dst": event.get("location", ""), "relation": "visits_location"})
        return [edge for edge in edges if edge["src"] and edge["dst"]]

    def _distribution(self, records: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
        total = max(len(records), 1)
        labels = Counter(record.get("label", "unknown") for record in records)
        categories = Counter(record.get("category", "unknown") for record in records)
        return {
            "labels": {key: round(value / total, 4) for key, value in labels.items()},
            "categories": {key: round(value / total, 4) for key, value in categories.items()},
        }
