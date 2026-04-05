from __future__ import annotations

from typing import Any

from synthetic_security_dataset_generator.core.base_generator import BaseGenerator
from synthetic_security_dataset_generator.core.labeling_engine import LabelDecision
from synthetic_security_dataset_generator.heuristics.vuln_patterns import VULNERABILITY_CATALOG


SNIPPETS = {
    ("sql_injection", "python"): {
        "vulnerable": """def lookup_user(conn, username):\n    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    return conn.execute(query).fetchall()\n""",
        "safe": """def lookup_user(conn, username):\n    query = \"SELECT * FROM users WHERE username = ?\"\n    return conn.execute(query, (username,)).fetchall()\n""",
    },
    ("command_injection", "python"): {
        "vulnerable": """import os\n\ndef backup(path):\n    os.system(f\"tar -czf /tmp/backup.tgz {path}\")\n""",
        "safe": """import subprocess\nfrom pathlib import Path\n\ndef backup(path):\n    safe_path = Path(path).resolve(strict=True)\n    subprocess.run([\"tar\", \"-czf\", \"/tmp/backup.tgz\", str(safe_path)], check=True)\n""",
    },
    ("xss", "javascript"): {
        "vulnerable": """function renderComment(comment) {\n  document.getElementById('feed').innerHTML += `<li>${comment}</li>`;\n}\n""",
        "safe": """function renderComment(comment) {\n  const item = document.createElement('li');\n  item.textContent = comment;\n  document.getElementById('feed').appendChild(item);\n}\n""",
    },
    ("insecure_deserialization", "python"): {
        "vulnerable": """import pickle\n\ndef load_profile(blob):\n    return pickle.loads(blob)\n""",
        "safe": """import json\n\ndef load_profile(blob):\n    return json.loads(blob)\n""",
    },
    ("path_traversal", "python"): {
        "vulnerable": """from pathlib import Path\n\ndef read_file(name):\n    return Path('/srv/data', name).read_text()\n""",
        "safe": """from pathlib import Path\n\ndef read_file(name):\n    base = Path('/srv/data').resolve()\n    target = (base / name).resolve()\n    if base not in target.parents:\n        raise ValueError('invalid path')\n    return target.read_text()\n""",
    },
    ("weak_crypto", "python"): {
        "vulnerable": """import hashlib\n\ndef digest(password):\n    return hashlib.md5(password.encode()).hexdigest()\n""",
        "safe": """import hashlib\nimport os\n\ndef digest(password, salt=None):\n    salt = salt or os.urandom(16)\n    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000).hex()\n""",
    },
    ("weak_crypto", "javascript"): {
        "vulnerable": """const crypto = require('crypto');\nfunction digest(password) {\n  return crypto.createHash('md5').update(password).digest('hex');\n}\n""",
        "safe": """const crypto = require('crypto');\nfunction digest(password, salt) {\n  return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256').toString('hex');\n}\n""",
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
        features = {
            "snippet_length": len(sample["vulnerable"]),
            "has_safe_version": True,
            "language": language,
            "severity_rank": ["low", "medium", "high", "critical"].index(descriptor["severity"]) + 1,
        }
        decision = LabelDecision(
            label="vulnerable",
            category=vulnerability_type,
            explanation=descriptor["explanation"],
            features=features,
            metadata={"severity": descriptor["severity"], "source": "synthetic_code_engine"},
        )
        record = {
            "language": language,
            "vulnerability_type": vulnerability_type,
            "severity": descriptor["severity"],
            "code_snippet": sample["vulnerable"],
            "safe_version": sample["safe"],
        }
        return self.labeling.attach(record, decision)
