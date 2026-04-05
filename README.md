# Synthetic Security Dataset Generator

Synthetic Security Dataset Generator is a research-grade Python platform for producing realistic, labeled synthetic security datasets for security analytics, anomaly detection, code security modeling, and LLM security workflows.

## At a glance

- Builds realistic synthetic datasets across phishing, attack telemetry, code security, and user behavior.
- Produces ML-ready outputs with labels, engineered features, manifests, quality scoring, and stratified splits.
- Supports graph-style relationship export for campaign, IP, domain, and user correlation workflows.
- Includes validation, reporting, benchmarking, and export modes designed for real data pipelines.

## Why this project matters

Security and AI teams need large, diverse, and explainable datasets, but real production telemetry is difficult to share because of privacy, legal, and operational risk. This platform generates realistic attack and normal-behavior data with labels, feature vectors, manifests, validation, and train/validation/test splits so teams can prototype detectors, benchmark ideas, and train models without touching sensitive production data.

Resume-ready summary:

Built a modular security data platform that generates high-fidelity synthetic datasets across phishing, multi-stage intrusion logs, vulnerable and secure code, and user-behavior anomalies; added reproducible generation, schema-aware validation, quality scoring, graph export, stratified train/validation/test splitting, ML-oriented export modes, dataset reporting, and end-to-end benchmarking for security detection use cases.

## Updated architecture

```text
synthetic-security-dataset-generator/
├── data/output/                                   # Generated datasets, manifests, split outputs
├── examples/
│   ├── benchmark.py                               # Multi-model phishing benchmark
│   └── train_simple_model.py                      # Original baseline demo
├── synthetic_security_dataset_generator/
│   ├── cli/main.py                                # Generate, validate, split, summarize
│   ├── core/
│   │   ├── base_generator.py
│   │   ├── config.py
│   │   ├── dataset_manager.py                     # Splits, manifests, metadata summaries
│   │   ├── labeling_engine.py
│   │   ├── randomness_engine.py
│   │   ├── reporting.py                           # Dataset report generation
│   │   ├── schema.py                              # Schema versioning and feature contracts
│   │   └── validator.py                           # Schema and quality checks
│   ├── dataset_generators/
│   │   ├── phishing_generator.py                  # Campaign-aware phishing + email context
│   │   ├── log_generator.py                       # Multi-stage campaigns with overlap and retries
│   │   ├── code_vuln_generator.py                 # Mixed safe/vulnerable code and localization labels
│   │   └── user_behavior_generator.py             # Long-term baseline behavior and anomalies
│   ├── exporters/
│   │   ├── csv_exporter.py
│   │   ├── graph_exporter.py                      # Edge list export for graph analytics
│   │   ├── json_exporter.py
│   │   └── parquet_exporter.py                    # Optional pyarrow-backed parquet export
│   ├── heuristics/
│   │   ├── attack_patterns.py
│   │   ├── phishing_patterns.py
│   │   └── vuln_patterns.py
│   └── utils/
│       ├── entropy_utils.py
│       ├── ml_utils.py
│       ├── record_utils.py
│       ├── string_utils.py
│       └── time_utils.py
└── tests/
```

## Major upgrades

- Advanced phishing realism: homoglyph domains, unicode brands, domain-age simulation, WHOIS-like metadata, hosting/ASN signals, path complexity, TLD risk, campaign clustering, and email lure context.
- Multi-stage intrusion telemetry: attack chains now include `recon -> scan -> initial access -> lateral movement -> exfiltration` with event linking, campaign IDs, multiple IPs, background noise, partial retries, and overlapping sessions.
- ML-ready code datasets: mixed vulnerable and safe samples, classification and localization modes, vulnerable line numbers, span indices, and CWE mappings.
- Baseline-aware user behavior: anomalies are generated relative to each user’s historical baseline and include weekly patterns, time-of-day behavior, long-term history summaries, risk scores, and session anomaly scores.
- Dataset operations: stratified splitting, schema versioning, feature inventories, quality scoring, imbalance analysis, graph extraction, report generation, and validation checks.
- Export flexibility: JSON, CSV, optional Parquet, flattening for tabular ML workflows, ML-friendly numeric flattening, edge-list graph export, and streaming-friendly writes.
- End-to-end benchmark: multi-model phishing benchmarking with accuracy, precision, recall, F1, and ROC-AUC.

## Dataset domains

### 1. Phishing URLs and malicious domains

The phishing generator now produces:

- Typosquatting and homoglyph attacks
- Unicode brand impersonation
- Punycode domains
- Suspicious keyword and path abuse
- Campaign-level URL clustering
- Email subject, sender, and lure context
- Benign brand and public web properties for balance
- Fake-but-realistic WHOIS and hosting metadata

Added ML features include:

- `levenshtein_distance_to_brand`
- `tld_risk_score`
- `domain_age_days`
- `has_unicode_chars`
- `path_depth`
- `path_complexity`

### 2. Multi-stage attack logs

The log generator now simulates campaign-driven intrusion sequences with:

- Multi-phase attack chains
- `attack_stage`
- `previous_event_id`
- `campaign_id`
- `overlap_window_id`
- Retry behavior and partial failures
- Different IPs across attacker stages
- Normal user activity and background noise mixed into the same session timeline

This makes the dataset usable for session classification, stage prediction, and graph/event correlation tasks.

### 3. Vulnerable and secure code

The code generator now supports mixed datasets:

- `label: vulnerable` and `label: safe`
- Classification mode
- Localization mode with vulnerable target lines
- Vulnerability spans and line numbers
- CWE mappings

This is suitable for secure-code classification, line-level localization, and remediation experiments.

### 4. User behavior and anomaly sequences

User-behavior generation now includes:

- Historical baselines per user
- Long-term history summaries
- Weekday versus weekend activity patterns
- Time-of-day distributions
- Relative anomaly generation instead of hard-coded global rules
- Event-level `risk_score`
- Session-level anomaly score
- Slow data exfiltration as a new low-and-slow anomaly

## CLI usage

Requirements:

- Python `3.9+`
- `pytest` for tests
- Optional: `pyarrow` for Parquet export

Install in editable mode:

```bash
python3 -m pip install -e .[dev]
```

Optional Parquet dependency:

```bash
python3 -m pip install pyarrow
```

Recommended end-to-end workflow:

```bash
python3 -m synthetic_security_dataset_generator.cli.main generate phishing --count 1000 --format json --graph-export
python3 -m synthetic_security_dataset_generator.cli.main validate phishing
python3 -m synthetic_security_dataset_generator.cli.main split phishing
python3 -m synthetic_security_dataset_generator.cli.main report phishing --report-format json
python3 examples/benchmark.py
```

Quick evaluation workflow:

```bash
python3 -m synthetic_security_dataset_generator.cli.main generate all --size small --format json --graph-export
python3 -m synthetic_security_dataset_generator.cli.main validate phishing
python3 -m synthetic_security_dataset_generator.cli.main report phishing --report-format json
python3 examples/benchmark.py
```

Generate:

```bash
python3 -m synthetic_security_dataset_generator.cli.main generate phishing --count 1000 --format json --graph-export
python3 -m synthetic_security_dataset_generator.cli.main generate logs --attack-type intrusion_chain --count 250
python3 -m synthetic_security_dataset_generator.cli.main generate code --code-mode localization --count 100
python3 -m synthetic_security_dataset_generator.cli.main generate all --size small --flatten --stream --chunk-size 250 --ml-format
```

Validate, split, summarize, report, graph:

```bash
python3 -m synthetic_security_dataset_generator.cli.main validate phishing --input-format json
python3 -m synthetic_security_dataset_generator.cli.main split phishing --train 0.7 --val 0.15 --test 0.15
python3 -m synthetic_security_dataset_generator.cli.main summarize logs
python3 -m synthetic_security_dataset_generator.cli.main report phishing --report-format json
python3 -m synthetic_security_dataset_generator.cli.main graph phishing
```

Run the benchmarks:

```bash
python3 examples/benchmark.py
```

## Manifest and validation

Each generated dataset writes a manifest containing:

- Dataset name and version
- Schema version
- Generation config
- Label distribution
- Category distribution
- Feature list
- Output file locations
- Split imbalance analysis
- Graph export locations when enabled

Typical generated artifacts in `data/output/`:

- `<dataset>.json|csv|parquet`
- `<dataset>_manifest.json`
- `<dataset>_split_manifest.json`
- `<dataset>_train.*`, `<dataset>_validation.*`, `<dataset>_test.*`
- `<dataset>_report.json|md`
- `<dataset>_graph.csv`

Validation checks currently cover:

- Required schema fields per dataset
- Required and optional feature contracts
- Extra-field detection
- Label/category consistency
- Feature completeness
- Label diversity sanity
- Realism heuristics
- Overall `quality_score` in `[0, 1]`

## Dataset Quality Score

Each dataset is assigned a `quality_score` between `0.0` and `1.0` by the validator. The score combines:

- Label diversity
- Feature completeness
- Distribution balance
- Basic realism heuristics per dataset type

Example:

```json
{
  "valid": true,
  "quality_score": 0.93,
  "issues": [],
  "warnings": []
}
```

Interpretation:

- `0.90+`: strong research/demo quality
- `0.75-0.89`: good usable dataset with moderate skew or realism gaps
- `<0.75`: dataset should be reviewed before using for benchmarking or training

## Example outputs

### Phishing sample

```json
{
  "url": "https://micrоsoft.support/identity/verify",
  "label": "phishing",
  "category": "homoglyph",
  "features": {
    "levenshtein_distance_to_brand": 4,
    "tld_risk_score": 0.64,
    "domain_age_days": 17,
    "has_unicode_chars": true,
    "path_complexity": 3.625
  },
  "metadata": {
    "campaign_id": "phishcamp-1a2b3c4d5e",
    "cluster_id": "cluster-5e4d3c2b1a",
    "email_context": {
      "sender_name": "Microsoft Security Team",
      "subject": "Unusual sign-in attempt on your Microsoft account"
    },
    "hosting": {
      "asn": "AS20473",
      "provider": "Choopa",
      "infra": "suspicious"
    },
    "whois": {
      "registrar": "Porkbun LLC",
      "privacy_protection": true
    }
  }
}
```

### Multi-stage log sample

```json
{
  "session_id": "sess-a2e4f87d11",
  "campaign_id": "camp-27d1c14ab9",
  "label": "intrusion_chain",
  "events": [
    {
      "event_id": "evt-b621ecc18c",
      "attack_stage": "recon",
      "previous_event_id": null,
      "overlap_window_id": "window-4",
      "ip": "45.83.64.17",
      "endpoint": "/robots.txt"
    },
    {
      "event_id": "evt-c7433e8c2d",
      "attack_stage": "data_exfiltration",
      "previous_event_id": "evt-901ff01792",
      "is_retry": false,
      "ip": "10.10.20.44",
      "endpoint": "/reports/export"
    }
  ]
}
```

### Code sample with localization

```json
{
  "label": "vulnerable",
  "vulnerability_type": "sql_injection",
  "cwe_id": "CWE-89",
  "vulnerable_line_numbers": [2],
  "vulnerability_spans": [
    {"line": 2, "start": 33, "end": 92}
  ]
}
```

### User behavior sample

```json
{
  "user_id": "user-4182",
  "label": "anomaly",
  "category": "slow_data_exfiltration",
  "features": {
    "session_anomaly_score": 0.392,
    "baseline_location_count": 2,
    "history_days": 173,
    "weekend_session": false
  }
}
```

### Report sample

```json
{
  "dataset_name": "phishing",
  "record_count": 100,
  "quality_score": 0.93,
  "anomalies_count": 35,
  "feature_stats": {
    "entropy": {"min": 2.6464, "max": 4.1147, "mean": 3.2861},
    "domain_age_days": {"min": 4.0, "max": 6111.0, "mean": 1673.93}
  }
}
```

## Sample Report Output

Example report generated by `python3 -m synthetic_security_dataset_generator.cli.main report phishing --report-format json`:

```json
{
  "dataset_name": "phishing",
  "record_count": 100,
  "label_distribution": {
    "phishing": 35,
    "benign": 50,
    "suspicious": 15
  },
  "quality_score": 0.93,
  "anomalies_count": 35,
  "feature_stats": {
    "entropy": {"min": 2.6464, "max": 4.1147, "mean": 3.2861},
    "domain_age_days": {"min": 4.0, "max": 6111.0, "mean": 1673.93}
  }
}
```

## Benchmark Results Table

Example results from `python3 examples/benchmark.py`:

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Random Threshold Forest | 0.8235 | 1.0000 | 0.6667 | 0.8000 | 0.8889 |

### Benchmark sample

```json
{
  "models": {
    "logistic_regression": {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1": 1.0, "roc_auc": 1.0},
    "random_threshold_forest": {"accuracy": 0.8235, "precision": 1.0, "recall": 0.6667, "f1": 0.8, "roc_auc": 0.8889}
  }
}
```

## ML Pipeline Notes

- Use `--ml-format` when exporting flattened numeric-friendly datasets for classic ML pipelines.
- Use JSON when nested sequence structure matters, especially for logs and user behavior.
- Use graph export when the downstream task involves campaign correlation, entity resolution, or graph analytics.
- Use localization mode in the code generator when training line-level vulnerability models.

## Limitations

- The data is synthetic and should be used for prototyping, benchmarking, and research, not as a substitute for production telemetry.
- Benchmark metrics may be optimistic because the data is generated from known heuristics rather than uncontrolled real-world distributions.
- Parquet export requires `pyarrow` and is intentionally optional to keep the core project lightweight.

## Research and production use cases

- Phishing URL classification and ranking
- Session-level attack chain detection
- Stage prediction and event-correlation experiments
- Graph analytics across campaigns, domains, users, and IPs
- Secure-code classification and vulnerability localization
- User-behavior analytics and anomaly scoring
- LLM finetuning and evaluation for security tasks


## Testing

Run:

```bash
python3 -m pytest
```

The test suite now covers:

- Generator correctness and feature presence
- Attack-chain linking
- Validation logic and quality scoring
- Stratified split correctness and imbalance analysis
- Manifest, report, and graph generation
- Schema checks for ML-ready outputs
