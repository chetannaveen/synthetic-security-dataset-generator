from __future__ import annotations

from typing import Any

from synthetic_security_dataset_generator.core.base_generator import BaseGenerator
from synthetic_security_dataset_generator.core.labeling_engine import LabelDecision
from synthetic_security_dataset_generator.heuristics.vuln_patterns import VULNERABILITY_CATALOG


SNIPPETS = {
    ("sql_injection", "python"): {
        "vulnerable": """def lookup_user(conn, username):\n    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    return conn.execute(query).fetchall()\n""",
        "safe": """def lookup_user(conn, username):\n    query = \"SELECT * FROM users WHERE username = ?\"\n    return conn.execute(query, (username,)).fetchall()\n""",
        "vulnerable_lines": [2],
    },
    ("command_injection", "python"): {
        "vulnerable": """import os\n\ndef backup(path):\n    os.system(f\"tar -czf /tmp/backup.tgz {path}\")\n""",
        "safe": """import subprocess\nfrom pathlib import Path\n\ndef backup(path):\n    safe_path = Path(path).resolve(strict=True)\n    subprocess.run([\"tar\", \"-czf\", \"/tmp/backup.tgz\", str(safe_path)], check=True)\n""",
        "vulnerable_lines": [4],
    },
    ("xss", "javascript"): {
        "vulnerable": """function renderComment(comment) {\n  document.getElementById('feed').innerHTML += `<li>${comment}</li>`;\n}\n""",
        "safe": """function renderComment(comment) {\n  const item = document.createElement('li');\n  item.textContent = comment;\n  document.getElementById('feed').appendChild(item);\n}\n""",
        "vulnerable_lines": [2],
    },
    ("insecure_deserialization", "python"): {
        "vulnerable": """import pickle\n\ndef load_profile(blob):\n    return pickle.loads(blob)\n""",
        "safe": """import json\n\ndef load_profile(blob):\n    return json.loads(blob)\n""",
        "vulnerable_lines": [4],
    },
    ("path_traversal", "python"): {
        "vulnerable": """from pathlib import Path\n\ndef read_file(name):\n    return Path('/srv/data', name).read_text()\n""",
        "safe": """from pathlib import Path\n\ndef read_file(name):\n    base = Path('/srv/data').resolve()\n    target = (base / name).resolve()\n    if base not in target.parents:\n        raise ValueError('invalid path')\n    return target.read_text()\n""",
        "vulnerable_lines": [4],
    },
    ("weak_crypto", "python"): {
        "vulnerable": """import hashlib\n\ndef digest(password):\n    return hashlib.md5(password.encode()).hexdigest()\n""",
        "safe": """import hashlib\nimport os\n\ndef digest(password, salt=None):\n    salt = salt or os.urandom(16)\n    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000).hex()\n""",
        "vulnerable_lines": [4],
    },
    ("weak_crypto", "javascript"): {
        "vulnerable": """const crypto = require('crypto');\nfunction digest(password) {\n  return crypto.createHash('md5').update(password).digest('hex');\n}\n""",
        "safe": """const crypto = require('crypto');\nfunction digest(password, salt) {\n  return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256').toString('hex');\n}\n""",
        "vulnerable_lines": [3],
    },
}


class VulnerableCodeGenerator(BaseGenerator):
    dataset_name = "code"

    def generate_record(self, malicious: bool | None = None, attack_type: str | None = None) -> dict[str, Any]:
        vulnerability_type = attack_type or self.random.choice(list(VULNERABILITY_CATALOG))
        descriptor = VULNERABILITY_CATALOG[vulnerability_type]
        available_languages = [
            language for language in descriptor["languages"] if (vulnerability_type, language) in SNIPPETS
        ]
        language = self.random.choice(available_languages)
        sample = SNIPPETS[(vulnerability_type, language)]
        is_vulnerable = bool(malicious if malicious is not None else self.random.weighted_choice([True, False], [0.6, 0.4]))
        label = "vulnerable" if is_vulnerable else "safe"
        code_snippet = sample["vulnerable"] if is_vulnerable else sample["safe"]
        vulnerable_spans = self._line_spans(code_snippet, sample["vulnerable_lines"]) if is_vulnerable else []
        features = {
            "snippet_length": len(code_snippet),
            "has_safe_version": True,
            "language": language,
            "severity_rank": ["low", "medium", "high", "critical"].index(descriptor["severity"]) + 1,
            "vulnerability_line_count": len(sample["vulnerable_lines"]) if is_vulnerable else 0,
        }
        explanation = descriptor["explanation"] if is_vulnerable else "Code uses the safe remediation pattern for this weakness family."
        decision = LabelDecision(
            label=label,
            category=vulnerability_type,
            explanation=explanation,
            features=features,
            metadata={
                "severity": descriptor["severity"],
                "source": "synthetic_code_engine",
                "cwe_id": descriptor["cwe"],
                "dataset_mode": self.config.code_dataset_mode,
            },
        )
        record = {
            "language": language,
            "vulnerability_type": vulnerability_type,
            "severity": descriptor["severity"],
            "cwe_id": descriptor["cwe"],
            "code_snippet": code_snippet,
            "safe_version": sample["safe"],
            "vulnerable_line_numbers": sample["vulnerable_lines"] if is_vulnerable else [],
            "vulnerability_spans": vulnerable_spans,
        }
        if self.config.code_dataset_mode == "localization":
            record["target_lines"] = sample["vulnerable_lines"] if is_vulnerable else []
        return self.labeling.attach(record, decision)

    def _line_spans(self, snippet: str, lines: list[int]) -> list[dict[str, int]]:
        spans: list[dict[str, int]] = []
        position = 0
        for line_number, line in enumerate(snippet.splitlines(keepends=True), start=1):
            start = position
            end = position + len(line)
            if line_number in lines:
                spans.append({"line": line_number, "start": start, "end": end})
            position = end
        return spans
