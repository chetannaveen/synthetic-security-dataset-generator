from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.core.dataset_manager import DatasetManager
from synthetic_security_dataset_generator.core.validator import DatasetValidator
from synthetic_security_dataset_generator.dataset_generators.phishing_generator import PhishingURLGenerator


def test_phishing_schema_fields_present():
    record = PhishingURLGenerator(GenerationConfig(dataset_name="phishing", count=1)).generate_dataset()[0]
    required = {"url", "label", "category", "explanation", "features", "metadata"}
    assert required.issubset(record.keys())


def test_validator_accepts_generated_dataset_and_scores_quality():
    records = PhishingURLGenerator(GenerationConfig(dataset_name="phishing", count=10, seed=21)).generate_dataset()
    result = DatasetValidator().validate(records, dataset_name="phishing")
    assert result["valid"] is True
    assert 0 <= result["quality_score"] <= 1


def test_stratified_split_preserves_labels():
    config = GenerationConfig(dataset_name="phishing", count=90, seed=12)
    records = PhishingURLGenerator(config).generate_dataset()
    manager = DatasetManager(config)
    splits = manager.split_dataset(records)
    analysis = manager.analyze_split_imbalance(records, splits)
    assert set(splits.keys()) == {"train", "validation", "test"}
    assert analysis["imbalance_by_label"]
    assert max(analysis["imbalance_by_label"].values()) < 0.3
