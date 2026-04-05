from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.dataset_generators.phishing_generator import PhishingURLGenerator


def test_phishing_schema_fields_present():
    record = PhishingURLGenerator(GenerationConfig(dataset_name="phishing", count=1)).generate_dataset()[0]
    required = {"url", "label", "category", "explanation", "features", "metadata"}
    assert required.issubset(record.keys())
