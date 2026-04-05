from synthetic_security_dataset_generator.core.validator import DatasetValidator
from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.dataset_generators.phishing_generator import PhishingURLGenerator


def test_phishing_schema_fields_present():
    record = PhishingURLGenerator(GenerationConfig(dataset_name="phishing", count=1)).generate_dataset()[0]
    required = {"url", "label", "category", "explanation", "features", "metadata"}
    assert required.issubset(record.keys())


def test_validator_accepts_generated_dataset():
    records = PhishingURLGenerator(GenerationConfig(dataset_name="phishing", count=10, seed=21)).generate_dataset()
    result = DatasetValidator().validate(records)
    assert result["valid"] is True
