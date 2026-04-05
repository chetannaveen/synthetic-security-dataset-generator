# Synthetic Security Dataset Generator

Synthetic Security Dataset Generator is a production-oriented Python project for creating realistic, labeled synthetic cybersecurity datasets for ML pipelines, anomaly detection systems, code security scanners, and LLM-based security tooling.

## Why it matters

Security teams often need large, diverse, and well-labeled datasets, but production telemetry and vulnerable code are hard to share because of privacy, legal, and safety constraints. This project generates high-signal synthetic data that preserves realistic structure, attack patterns, timelines, and explanatory metadata without exposing real customer data.

Resume-ready summary:

Built a modular Python platform that generates realistic synthetic cybersecurity datasets across phishing, attack telemetry, vulnerable code, and user behavior anomaly domains; included centralized labeling, reproducible randomness, feature extraction, CSV/JSON exports, time-series attack simulation, and a pluggable CLI architecture suitable for security research and AI training pipelines.

## Architecture

```text
synthetic-security-dataset-generator/
├── data/output/                         # Generated datasets
├── synthetic_security_dataset_generator/
│   ├── cli/main.py                      # CLI entrypoint and generator registry
│   ├── core/
│   │   ├── base_generator.py            # Abstract generator with balancing and summaries
│   │   ├── config.py                    # Shared generation configuration
│   │   ├── labeling_engine.py           # Centralized labels, features, and explanations
│   │   └── randomness_engine.py         # Seeded randomness for reproducibility
│   ├── dataset_generators/
│   │   ├── phishing_generator.py        # Phishing and benign URL generation
│   │   ├── log_generator.py             # Time-consistent log session generation
│   │   ├── code_vuln_generator.py       # Vulnerable code and safe remediations
│   │   └── user_behavior_generator.py   # User behavior and anomaly sequences
│   ├── exporters/
│   │   ├── csv_exporter.py
│   │   └── json_exporter.py
│   ├── heuristics/
│   │   ├── attack_patterns.py
│   │   ├── phishing_patterns.py
│   │   └── vuln_patterns.py
│   └── utils/
│       ├── entropy_utils.py
│       ├── string_utils.py
│       └── time_utils.py
└── tests/
```

## Advanced capabilities implemented

- Controlled randomness engine with explicit seeds for reproducibility.
- Feature extraction pipeline attached to every record through the labeling engine.
- Dataset balancing logic for malicious versus benign ratios.
- Attack scenario templates for phishing, traffic, code, and user anomalies.
- Time-series simulation for logs and behavior sequences.
- Entropy calculations for phishing-domain realism.
- Pluggable generator system through a CLI registry and shared base interface.

## Dataset types

### 1. Phishing URLs / Malicious domains

Produces balanced benign, suspicious, and phishing URLs with:

- Typosquatting
- Subdomain abuse
- Keyword abuse
- Punycode-based impersonation
- Brand impersonation for Microsoft, Google, Apple, Amazon, PayPal, and banks

Each record includes ML-ready features such as entropy, subdomain count, keyword presence, and brand resemblance.

### 2. Network and server attack logs

Produces session-grouped synthetic traffic for:

- SSH authentication flows
- Web server and API access events
- Brute force
- Credential stuffing
- Scanning
- DDoS bursts
- Admin endpoint probing

Each sequence is timestamped, time-consistent, and exported as grouped events with a session-level label.

### 3. Vulnerable code samples

Produces compact vulnerable code examples with safe remediations for:

- SQL injection
- Command injection
- XSS
- Insecure deserialization
- Path traversal
- Weak crypto usage

Each sample includes severity, explanation, language, vulnerable snippet, and a corrected safe version.

### 4. User behavior and anomaly sequences

Produces realistic user sessions covering:

- Standard login and navigation flows
- New geography logins
- Impossible travel
- High-frequency actions
- Privilege escalation attempts

Each sequence includes user IDs, timestamps, locations, IPs, anomaly labels, and explanatory metadata.

## CLI usage

Install in editable mode:

```bash
python -m pip install -e .[dev]
```

Generate datasets:

```bash
python -m synthetic_security_dataset_generator.cli.main generate phishing --count 1000 --format json
python -m synthetic_security_dataset_generator.cli.main generate logs --attack-type brute_force --count 250
python -m synthetic_security_dataset_generator.cli.main generate code --attack-type sql_injection --count 50
python -m synthetic_security_dataset_generator.cli.main generate all --size small --format csv
ssdg generate user_behavior --count 500 --malicious-ratio 0.2
```

## Output schema

Every generated record contains:

- `label`
- `category`
- `explanation`
- `features`
- `metadata`

Dataset-specific fields are added on top:

- `url` for phishing
- `events` and `session_id` for log and user-behavior sequences
- `code_snippet`, `safe_version`, `language`, `severity`, `vulnerability_type` for code samples

## Example outputs

### Phishing sample

```json
{
  "url": "https://secure-login.microsoft.verify-user.com/session",
  "label": "phishing",
  "category": "subdomain_abuse",
  "explanation": "URL exhibits subdomain_abuse indicators targeting microsoft, consistent with phishing infrastructure.",
  "features": {
    "domain_length": 40,
    "entropy": 4.0128,
    "number_of_subdomains": 3,
    "contains_keyword": true,
    "looks_like_brand": true
  },
  "metadata": {
    "brand_target": "microsoft",
    "source": "synthetic_url_engine"
  }
}
```

### Attack log session sample

```json
{
  "session_id": "sess-6ba7fe1234",
  "label": "scan",
  "category": "scan",
  "events": [
    {
      "timestamp": "2026-04-04T11:18:52Z",
      "ip": "45.83.64.19",
      "endpoint": "/.env",
      "status_code": 404,
      "user_agent": "curl/8.4.0"
    }
  ]
}
```

### Vulnerable code sample

```python
def lookup_user(conn, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()
```

Safe remediation:

```python
def lookup_user(conn, username):
    query = "SELECT * FROM users WHERE username = ?"
    return conn.execute(query, (username,)).fetchall()
```

## Testing

Run:

```bash
pytest
```

The tests cover generator correctness, export flow, labeling presence, and schema validation.
