from __future__ import annotations

from collections import Counter
from typing import Any


class DatasetValidator:
    REQUIRED_FIELDS = {"label", "category", "explanation", "features", "metadata"}

    def validate(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        issues: list[str] = []
        if not records:
            return {"valid": False, "issues": ["dataset is empty"], "stats": {}}

        missing_fields = 0
        inconsistent_labels = 0
        incomplete_features = 0
        labels = Counter()
        feature_keys: set[str] = set()

        for record in records:
            labels[record.get("label", "unknown")] += 1
            missing = self.REQUIRED_FIELDS - set(record.keys())
            if missing:
                missing_fields += 1
                issues.append(f"record missing required fields: {sorted(missing)}")
            features = record.get("features", {})
            if not isinstance(features, dict) or not features:
                incomplete_features += 1
                issues.append("record has empty or invalid features")
            else:
                feature_keys.update(features.keys())
            if record.get("label") in {"phishing", "anomaly"} and record.get("category") in {"legitimate", "normal"}:
                inconsistent_labels += 1
                issues.append("label/category mismatch detected")

        stats = {
            "record_count": len(records),
            "label_distribution": dict(labels),
            "feature_count": len(feature_keys),
            "missing_field_records": missing_fields,
            "inconsistent_label_records": inconsistent_labels,
            "incomplete_feature_records": incomplete_features,
        }
        if len(labels) == 1:
            issues.append("dataset has a single label only; poor ML training diversity")
        return {"valid": not issues, "issues": issues, "stats": stats}
