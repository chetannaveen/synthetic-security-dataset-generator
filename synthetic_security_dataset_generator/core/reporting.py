from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.core.validator import DatasetValidator


class DatasetReporter:
    def generate(self, dataset_name: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        validator_result = DatasetValidator().validate(records, dataset_name=dataset_name)
        feature_stats = self._feature_stats(records)
        anomalies_count = sum(record.get("label") in {"phishing", "anomaly", "vulnerable"} for record in records)
        return {
            "dataset_name": dataset_name,
            "record_count": len(records),
            "label_distribution": dict(Counter(record.get("label", "unknown") for record in records)),
            "category_distribution": dict(Counter(record.get("category", "unknown") for record in records)),
            "feature_stats": feature_stats,
            "anomalies_count": anomalies_count,
            "quality_score": validator_result["quality_score"],
            "warnings": validator_result["warnings"],
            "issues": validator_result["issues"],
        }

    def write_json(self, report: dict[str, Any], destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return destination

    def write_markdown(self, report: dict[str, Any], destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# Dataset Report: {report['dataset_name']}",
            "",
            f"- Records: {report['record_count']}",
            f"- Quality Score: {report['quality_score']}",
            f"- Anomalies Count: {report['anomalies_count']}",
            "",
            "## Label Distribution",
        ]
        for label, count in report["label_distribution"].items():
            lines.append(f"- {label}: {count}")
        lines.append("")
        lines.append("## Feature Stats")
        for feature, stats in report["feature_stats"].items():
            lines.append(f"- {feature}: min={stats['min']}, max={stats['max']}, mean={stats['mean']}")
        destination.write_text("\n".join(lines), encoding="utf-8")
        return destination

    def _feature_stats(self, records: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
        numeric_features: dict[str, list[float]] = {}
        for record in records:
            for key, value in record.get("features", {}).items():
                if isinstance(value, bool):
                    numeric_features.setdefault(key, []).append(float(value))
                elif isinstance(value, (int, float)):
                    numeric_features.setdefault(key, []).append(float(value))
        stats: dict[str, dict[str, float]] = {}
        for feature, values in numeric_features.items():
            stats[feature] = {
                "min": round(min(values), 4),
                "max": round(max(values), 4),
                "mean": round(sum(values) / len(values), 4),
            }
        return stats
