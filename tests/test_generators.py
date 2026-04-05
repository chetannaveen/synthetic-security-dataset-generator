from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.dataset_generators.code_vuln_generator import VulnerableCodeGenerator
from synthetic_security_dataset_generator.dataset_generators.log_generator import AttackLogGenerator
from synthetic_security_dataset_generator.dataset_generators.phishing_generator import PhishingURLGenerator
from synthetic_security_dataset_generator.dataset_generators.user_behavior_generator import UserBehaviorGenerator


def test_phishing_generator_produces_mixed_labels():
    generator = PhishingURLGenerator(GenerationConfig(dataset_name="phishing", count=30, seed=7))
    records = generator.generate_dataset()
    labels = {record["label"] for record in records}
    assert {"benign", "phishing", "suspicious"}.issubset(labels)
    assert all("features" in record for record in records)
    assert "levenshtein_distance_to_brand" in records[0]["features"]
    assert "whois" in records[0]["metadata"]


def test_attack_logs_include_session_grouping_and_stages():
    generator = AttackLogGenerator(GenerationConfig(dataset_name="logs", count=10, seed=11, malicious_ratio=1.0))
    records = generator.generate_dataset()
    assert all(record["events"] for record in records)
    assert all(record["session_id"] == record["metadata"]["session_id"] for record in records)
    assert any(event["attack_stage"] != "normal" for event in records[0]["events"])
    assert any(event["previous_event_id"] for event in records[0]["events"][1:])


def test_code_samples_include_safe_versions_and_safe_labels():
    generator = VulnerableCodeGenerator(GenerationConfig(dataset_name="code", count=20, seed=3))
    records = generator.generate_dataset()
    assert all(record["safe_version"] for record in records)
    assert {"vulnerable", "safe"} == {record["label"] for record in records}
    assert all("cwe_id" in record for record in records)


def test_user_behavior_flags_anomalies():
    generator = UserBehaviorGenerator(GenerationConfig(dataset_name="user_behavior", count=20, seed=5))
    records = generator.generate_dataset()
    assert any(record["label"] == "anomaly" for record in records)
    assert any(record["label"] == "normal" for record in records)
    assert "baseline" in records[0]["metadata"]
    assert "session_anomaly_score" in records[0]["features"]
