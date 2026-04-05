# Synthetic Security Dataset Generator

Synthetic Security Dataset Generator is a research-grade Python platform for producing realistic, labeled synthetic security datasets for security analytics, anomaly detection, code security modeling, and LLM security workflows.

## Why this project matters

Security and AI teams need large, diverse, and explainable datasets, but real production telemetry is difficult to share because of privacy, legal, and operational risk. This platform generates realistic attack and normal-behavior data with labels, feature vectors, manifests, validation, and train/validation/test splits so teams can prototype detectors, benchmark ideas, and train models without touching sensitive production data.

Resume-ready summary:

Built a modular security data platform that generates high-fidelity synthetic datasets across phishing, multi-stage intrusion logs, vulnerable and secure code, and user-behavior anomalies; added reproducible generation, feature engineering, dataset validation, manifests, train/validation/test splitting, streaming exports, and an end-to-end ML demo for security detection use cases.

## Updated architecture

```text
synthetic-security-dataset-generator/
├── data/output/                                   # Generated datasets, manifests, split outputs
├── examples/
│   └── train_simple_model.py                      # Baseline phishing classifier demo
├── synthetic_security_dataset_generator/
│   ├── cli/main.py                                # Generate, validate, split, summarize
│   ├── core/
│   │   ├── base_generator.py
│   │   ├── config.py
│   │   ├── dataset_manager.py                     # Splits, manifests, metadata summaries
│   │   ├── labeling_engine.py
│   │   ├── randomness_engine.py
│   │   └── validator.py                           # Schema and quality checks
│   ├── dataset_generators/
│   │   ├── phishing_generator.py                  # Homoglyphs, WHOIS, hosting, domain-age realism
│   │   ├── log_generator.py                       # Multi-stage campaigns with event chaining
│   │   ├── code_vuln_generator.py                 # Mixed safe/vulnerable code and localization labels
│   │   └── user_behavior_generator.py             # Baseline-aware time-series behavior and anomalies
│   ├── exporters/
│   │   ├── csv_exporter.py
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

- Advanced phishing realism: homoglyph domains, unicode brands, domain-age simulation, WHOIS-like metadata, hosting/ASN signals, path complexity, TLD risk, and edit-distance features.
- Multi-stage intrusion telemetry: attack chains now include `recon -> scan -> initial access -> lateral movement -> exfiltration` with event linking, campaign IDs, multiple IPs, and realistic time progression mixed with benign traffic.
- ML-ready code datasets: mixed vulnerable and safe samples, classification and localization modes, vulnerable line numbers, span indices, and CWE mappings.
- Baseline-aware user behavior: anomalies are generated relative to each user’s historical baseline and include risk scores plus session anomaly scores.
- Dataset operations: versioned manifests, feature inventories, dataset splitting, summaries, and validation checks.
- Export flexibility: JSON, CSV, optional Parquet, flattening for tabular ML workflows, and streaming-friendly JSON writes.
- End-to-end benchmark: a baseline phishing classifier in `examples/train_simple_model.py`.

## Dataset domains

### 1. Phishing URLs and malicious domains

The phishing generator now produces:

- Typosquatting and homoglyph attacks
- Unicode brand impersonation
- Punycode domains
- Suspicious keyword and path abuse
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
- Different IPs across attacker stages
- Normal user activity mixed into the same session timeline

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
- Relative anomaly generation instead of hard-coded global rules
- Event-level `risk_score`
- Session-level anomaly score
- Slow data exfiltration as a new low-and-slow anomaly

## CLI usage

Install in editable mode:

```bash
python3 -m pip install -e .[dev]
```

Generate:

```bash
python3 -m synthetic_security_dataset_generator.cli.main generate phishing --count 1000 --format json
python3 -m synthetic_security_dataset_generator.cli.main generate logs --attack-type intrusion_chain --count 250
python3 -m synthetic_security_dataset_generator.cli.main generate code --code-mode localization --count 100
python3 -m synthetic_security_dataset_generator.cli.main generate all --size small --flatten --stream
```

Validate, split, summarize:

```bash
python3 -m synthetic_security_dataset_generator.cli.main validate phishing --input-format json
python3 -m synthetic_security_dataset_generator.cli.main split phishing --train 0.7 --val 0.15 --test 0.15
python3 -m synthetic_security_dataset_generator.cli.main summarize logs
```

Run the demo model:

```bash
python3 examples/train_simple_model.py
```

## Manifest and validation

Each generated dataset writes a manifest containing:

- Dataset name and version
- Generation config
- Label distribution
- Category distribution
- Feature list
- Output file locations

Validation checks currently cover:

- Required schema fields
- Label/category consistency
- Feature completeness
- Label diversity sanity

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
      "ip": "45.83.64.17",
      "endpoint": "/robots.txt"
    },
    {
      "event_id": "evt-c7433e8c2d",
      "attack_stage": "data_exfiltration",
      "previous_event_id": "evt-901ff01792",
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
    "baseline_location_count": 2
  }
}
```

## Research and production use cases

- Phishing URL classification and ranking
- Session-level attack chain detection
- Stage prediction and event-correlation experiments
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
- Validation logic
- Manifest and split generation
- Schema checks for ML-ready outputs
