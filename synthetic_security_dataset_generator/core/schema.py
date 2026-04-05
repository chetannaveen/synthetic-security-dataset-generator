from __future__ import annotations

from typing import Any


SCHEMA_VERSION = "2026.04"

DATASET_SCHEMAS: dict[str, dict[str, Any]] = {
    "common": {
        "version": SCHEMA_VERSION,
        "required_fields": {"label", "category", "explanation", "features", "metadata"},
        "optional_fields": {"relationships"},
    },
    "phishing": {
        "version": SCHEMA_VERSION,
        "required_fields": {"url"},
        "optional_fields": {"campaign_id", "cluster_id"},
        "required_features": {
            "domain_length",
            "entropy",
            "number_of_subdomains",
            "contains_keyword",
            "looks_like_brand",
            "levenshtein_distance_to_brand",
            "tld_risk_score",
            "domain_age_days",
            "has_unicode_chars",
            "path_depth",
            "path_complexity",
        },
        "optional_features": {"campaign_frequency_hint"},
    },
    "logs": {
        "version": SCHEMA_VERSION,
        "required_fields": {"session_id", "events"},
        "optional_fields": {"campaign_id", "overlap_window_id"},
        "required_features": {
            "request_count",
            "unique_endpoints",
            "error_rate",
            "duration_seconds",
            "attack_stage_count",
            "distinct_ips",
        },
        "optional_features": {"background_noise_events", "retry_ratio"},
    },
    "code": {
        "version": SCHEMA_VERSION,
        "required_fields": {"language", "vulnerability_type", "severity", "cwe_id", "code_snippet", "safe_version"},
        "optional_fields": {"target_lines", "vulnerable_line_numbers", "vulnerability_spans"},
        "required_features": {
            "snippet_length",
            "has_safe_version",
            "language",
            "severity_rank",
            "vulnerability_line_count",
        },
        "optional_features": set(),
    },
    "user_behavior": {
        "version": SCHEMA_VERSION,
        "required_fields": {"user_id", "events"},
        "optional_fields": {"history_summary"},
        "required_features": {
            "event_count",
            "distinct_locations",
            "action_velocity",
            "contains_admin_action",
            "session_anomaly_score",
            "baseline_location_count",
        },
        "optional_features": {"weekend_session", "history_days"},
    },
}


def get_schema(dataset_name: str) -> dict[str, Any]:
    common = DATASET_SCHEMAS["common"]
    specific = DATASET_SCHEMAS.get(dataset_name, {})
    return {
        "version": specific.get("version", common["version"]),
        "required_fields": set(common["required_fields"]) | set(specific.get("required_fields", set())),
        "optional_fields": set(common.get("optional_fields", set())) | set(specific.get("optional_fields", set())),
        "required_features": set(specific.get("required_features", set())),
        "optional_features": set(specific.get("optional_features", set())),
    }
