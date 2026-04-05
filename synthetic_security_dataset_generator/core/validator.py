from __future__ import annotations

from collections import Counter
from typing import Any

from synthetic_security_dataset_generator.core.schema import get_schema


class DatasetValidator:
    def validate(self, records: list[dict[str, Any]], dataset_name: str | None = None) -> dict[str, Any]:
        issues: list[str] = []
        warnings: list[str] = []
        if not records:
            return {"valid": False, "quality_score": 0.0, "issues": ["dataset is empty"], "warnings": [], "stats": {}}

        inferred_dataset = dataset_name or self._infer_dataset(records[0])
        schema = get_schema(inferred_dataset)
        missing_fields = 0
        extra_fields = Counter()
        inconsistent_labels = 0
        incomplete_features = 0
        labels = Counter()
        feature_keys: set[str] = set()
        realism_hits = 0

        for record in records:
            labels[record.get("label", "unknown")] += 1
            record_keys = set(record.keys())
            missing = schema["required_fields"] - record_keys
            if missing:
                missing_fields += 1
                issues.append(f"record missing required fields: {sorted(missing)}")
            extra = record_keys - schema["required_fields"] - schema["optional_fields"]
            for field in extra:
                extra_fields[field] += 1

            features = record.get("features", {})
            if not isinstance(features, dict) or not features:
                incomplete_features += 1
                issues.append("record has empty or invalid features")
            else:
                feature_keys.update(features.keys())
                missing_features = schema["required_features"] - set(features.keys())
                if missing_features:
                    incomplete_features += 1
                    issues.append(f"record missing required features: {sorted(missing_features)}")

            if record.get("label") in {"phishing", "anomaly"} and record.get("category") in {"legitimate", "normal"}:
                inconsistent_labels += 1
                issues.append("label/category mismatch detected")

            realism_hits += self._realism_score(record, inferred_dataset)

        if len(labels) == 1:
            warnings.append("dataset has a single label only; poor ML training diversity")
        if extra_fields:
            warnings.append(f"extra fields observed: {sorted(extra_fields.keys())}")

        diversity_score = min(len(labels) / 3, 1.0)
        completeness_score = max(0.0, 1 - ((missing_fields + incomplete_features) / max(len(records), 1)))
        balance_score = self._balance_score(labels)
        realism_score = realism_hits / max(len(records), 1)
        quality_score = round((0.25 * diversity_score) + (0.35 * completeness_score) + (0.2 * balance_score) + (0.2 * realism_score), 4)

        stats = {
            "record_count": len(records),
            "dataset_name": inferred_dataset,
            "schema_version": schema["version"],
            "label_distribution": dict(labels),
            "feature_count": len(feature_keys),
            "missing_field_records": missing_fields,
            "inconsistent_label_records": inconsistent_labels,
            "incomplete_feature_records": incomplete_features,
        }
        return {
            "valid": not issues,
            "quality_score": quality_score,
            "issues": sorted(set(issues)),
            "warnings": sorted(set(warnings)),
            "stats": stats,
        }

    def _infer_dataset(self, record: dict[str, Any]) -> str:
        if "url" in record:
            return "phishing"
        if "session_id" in record and "events" in record:
            return "logs"
        if "code_snippet" in record:
            return "code"
        if "user_id" in record and "events" in record:
            return "user_behavior"
        return "unknown"

    def _balance_score(self, labels: Counter) -> float:
        total = sum(labels.values()) or 1
        ratios = [count / total for count in labels.values()]
        return round(1 - (max(ratios) - min(ratios) if len(ratios) > 1 else 1), 4)

    def _realism_score(self, record: dict[str, Any], dataset_name: str) -> float:
        if dataset_name == "phishing":
            features = record.get("features", {})
            metadata = record.get("metadata", {})
            return float(
                "whois" in metadata
                and "hosting" in metadata
                and features.get("domain_age_days", 0) >= 0
                and "campaign_id" in metadata
            )
        if dataset_name == "logs":
            events = record.get("events", [])
            has_chain = any(event.get("previous_event_id") for event in events[1:]) if len(events) > 1 else False
            has_overlap = any(event.get("overlap_window_id") for event in events)
            return float(has_chain and has_overlap)
        if dataset_name == "code":
            return float(bool(record.get("cwe_id")) and isinstance(record.get("vulnerability_spans"), list))
        if dataset_name == "user_behavior":
            metadata = record.get("metadata", {})
            return float("baseline" in metadata and "history_summary" in metadata)
        return 0.0
