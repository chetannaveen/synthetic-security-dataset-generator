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


def test_attack_logs_include_session_grouping():
    generator = AttackLogGenerator(GenerationConfig(dataset_name="logs", count=10, seed=11))
    records = generator.generate_dataset()
    assert all(record["events"] for record in records)
    assert all(record["session_id"] == record["metadata"]["session_id"] for record in records)


def test_code_samples_include_safe_versions():
    generator = VulnerableCodeGenerator(GenerationConfig(dataset_name="code", count=5, seed=3))
    records = generator.generate_dataset()
    assert all(record["safe_version"] for record in records)
    assert all(record["label"] == "vulnerable" for record in records)


def test_user_behavior_flags_anomalies():
    generator = UserBehaviorGenerator(GenerationConfig(dataset_name="user_behavior", count=20, seed=5))
    records = generator.generate_dataset()
    assert any(record["label"] == "anomaly" for record in records)
    assert any(record["label"] == "normal" for record in records)
