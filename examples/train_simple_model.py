from __future__ import annotations

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from synthetic_security_dataset_generator.utils.ml_utils import dot_product, sigmoid
from synthetic_security_dataset_generator.utils.record_utils import load_records


FEATURES = [
    "domain_length",
    "entropy",
    "number_of_subdomains",
    "contains_keyword",
    "looks_like_brand",
    "levenshtein_distance_to_brand",
    "tld_risk_score",
    "domain_age_days",
    "has_unicode_chars",
    "path_depth",
    "path_complexity",
]


def vectorize(record: dict) -> list[float]:
    features = record["features"]
    values = []
    for feature in FEATURES:
        value = features.get(feature, 0)
        if isinstance(value, bool):
            values.append(1.0 if value else 0.0)
        else:
            values.append(float(value))
    return values


def fit_normalization(samples: list[list[float]]) -> list[float]:
    columns = list(zip(*samples))
    return [max(column) if max(column) else 1.0 for column in columns]


def apply_normalization(samples: list[list[float]], maxima: list[float]) -> list[list[float]]:
    return [[value / maxima[index] for index, value in enumerate(sample)] for sample in samples]


def train(records: list[dict], epochs: int = 250, learning_rate: float = 0.35) -> tuple[list[float], float, list[float]]:
    raw = [vectorize(record) for record in records]
    maxima = fit_normalization(raw)
    x = apply_normalization(raw, maxima)
    y = [1.0 if record["label"] == "phishing" else 0.0 for record in records]
    weights = [0.0 for _ in FEATURES]
    bias = 0.0
    for _ in range(epochs):
        for sample, target in zip(x, y):
            prediction = sigmoid(dot_product(weights, sample) + bias)
            error = prediction - target
            for index, value in enumerate(sample):
                weights[index] -= learning_rate * error * value
            bias -= learning_rate * error
    return weights, bias, maxima


def evaluate(records: list[dict], weights: list[float], bias: float, maxima: list[float]) -> dict[str, float]:
    x = apply_normalization([vectorize(record) for record in records], maxima)
    y = [1 if record["label"] == "phishing" else 0 for record in records]
    correct = 0
    positives = 0
    predicted_positives = 0
    true_positives = 0
    for sample, target in zip(x, y):
        prediction = 1 if sigmoid(dot_product(weights, sample) + bias) >= 0.35 else 0
        correct += prediction == target
        positives += target
        predicted_positives += prediction
        true_positives += prediction == target == 1
    precision = true_positives / predicted_positives if predicted_positives else 0.0
    recall = true_positives / positives if positives else 0.0
    return {
        "accuracy": round(correct / len(y), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def main() -> None:
    dataset_path = Path("data/output/phishing.json")
    records = load_records(dataset_path)
    train_cutoff = int(len(records) * 0.8)
    train_records = records[:train_cutoff]
    test_records = records[train_cutoff:]
    weights, bias, maxima = train(train_records)
    metrics = evaluate(test_records, weights, bias, maxima)
    print(json.dumps({"features": FEATURES, "metrics": metrics}, indent=2))


if __name__ == "__main__":
    main()
