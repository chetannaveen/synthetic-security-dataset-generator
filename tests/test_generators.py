from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.dataset_generators.code_vuln_generator import VulnerableCodeGenerator
from synthetic_security_dataset_generator.dataset_generators.log_generator import AttackLogGenerator
from synthetic_security_dataset_generator.dataset_generators.phishing_generator import PhishingURLGenerator
from synthetic_security_dataset_generator.dataset_generators.user_behavior_generator import UserBehaviorGenerator


def test_phishing_generator_produces_campaign_context():
    generator = PhishingURLGenerator(GenerationConfig(dataset_name="phishing", count=30, seed=7))
    records = generator.generate_dataset()
    labels = {record["label"] for record in records}
    assert {"benign", "phishing", "suspicious"}.issubset(labels)
    assert all("features" in record for record in records)
    assert "levenshtein_distance_to_brand" in records[0]["features"]
    phishing = next(record for record in records if record["label"] == "phishing")
    assert "whois" in phishing["metadata"]
    assert phishing["metadata"]["email_context"]["subject"]


def test_attack_logs_include_stages_retries_and_overlap():
    generator = AttackLogGenerator(GenerationConfig(dataset_name="logs", count=10, seed=11, malicious_ratio=1.0))
    records = generator.generate_dataset()
    first = records[0]
    assert all(record["events"] for record in records)
    assert first["session_id"] == first["metadata"]["session_id"]
    assert any(event["attack_stage"] != "normal" for event in first["events"])
    assert any(event["previous_event_id"] for event in first["events"][1:])
    assert any(event["overlap_window_id"] for event in first["events"])


def test_code_samples_include_safe_versions_and_cwe():
    generator = VulnerableCodeGenerator(GenerationConfig(dataset_name="code", count=20, seed=3))
    records = generator.generate_dataset()
    assert all(record["safe_version"] for record in records)
    assert {"vulnerable", "safe"} == {record["label"] for record in records}
    assert all("cwe_id" in record for record in records)


def test_user_behavior_contains_history_and_scores():
    generator = UserBehaviorGenerator(GenerationConfig(dataset_name="user_behavior", count=20, seed=5))
    records = generator.generate_dataset()
    assert any(record["label"] == "anomaly" for record in records)
    assert any(record["label"] == "normal" for record in records)
    assert "baseline" in records[0]["metadata"]
    assert "history_summary" in records[0]["metadata"]
    assert "session_anomaly_score" in records[0]["features"]
