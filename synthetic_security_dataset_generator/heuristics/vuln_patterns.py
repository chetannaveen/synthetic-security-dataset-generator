VULNERABILITY_CATALOG = {
    "sql_injection": {
        "severity": "high",
        "languages": ["python", "javascript"],
        "explanation": "User-controlled input is concatenated into a SQL query without parameterization.",
    },
    "command_injection": {
        "severity": "critical",
        "languages": ["python", "javascript"],
        "explanation": "Untrusted input reaches a shell command interpreter.",
    },
    "xss": {
        "severity": "medium",
        "languages": ["javascript"],
        "explanation": "Untrusted data is inserted into an HTML response without output encoding.",
    },
    "insecure_deserialization": {
        "severity": "high",
        "languages": ["python"],
        "explanation": "Serialized attacker-controlled data is deserialized into executable objects.",
    },
    "path_traversal": {
        "severity": "high",
        "languages": ["python", "javascript"],
        "explanation": "User input controls a filesystem path with insufficient normalization.",
    },
    "weak_crypto": {
        "severity": "medium",
        "languages": ["python", "javascript"],
        "explanation": "Deprecated or reversible cryptographic primitives are used for secrets.",
    },
}
