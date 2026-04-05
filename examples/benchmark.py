from __future__ import annotations

import json
import math
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.core.dataset_manager import DatasetManager
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
    vector = []
    for feature in FEATURES:
        value = record["features"].get(feature, 0)
        if isinstance(value, bool):
            vector.append(float(value))
        else:
            vector.append(float(value))
    return vector


def normalize(samples: list[list[float]]) -> tuple[list[list[float]], list[float]]:
    columns = list(zip(*samples))
    maxima = [max(column) if max(column) else 1.0 for column in columns]
    normalized = [[value / maxima[index] for index, value in enumerate(sample)] for sample in samples]
    return normalized, maxima


def apply_normalization(samples: list[list[float]], maxima: list[float]) -> list[list[float]]:
    return [[value / maxima[index] for index, value in enumerate(sample)] for sample in samples]


class LogisticRegressionBaseline:
    def __init__(self, epochs: int = 300, learning_rate: float = 0.2) -> None:
        self.epochs = epochs
        self.learning_rate = learning_rate
        self.weights: list[float] = []
        self.bias = 0.0
        self.maxima: list[float] = []

    def fit(self, x: list[list[float]], y: list[int]) -> None:
        normalized, self.maxima = normalize(x)
        self.weights = [0.0 for _ in normalized[0]]
        self.bias = 0.0
        for _ in range(self.epochs):
            for sample, target in zip(normalized, y):
                prediction = sigmoid(dot_product(self.weights, sample) + self.bias)
                error = prediction - target
                for index, value in enumerate(sample):
                    self.weights[index] -= self.learning_rate * error * value
                self.bias -= self.learning_rate * error

    def predict_proba(self, x: list[list[float]]) -> list[float]:
        normalized = apply_normalization(x, self.maxima)
        return [sigmoid(dot_product(self.weights, sample) + self.bias) for sample in normalized]


class RandomThresholdForest:
    def __init__(self, trees: int = 25, threshold_seed: int = 1337) -> None:
        self.trees = trees
        self.threshold_seed = threshold_seed
        self.rules: list[tuple[int, float, float]] = []

    def fit(self, x: list[list[float]], y: list[int]) -> None:
        import random

        rng = random.Random(self.threshold_seed)
        feature_count = len(x[0])
        self.rules = []
        positives = [sample for sample, label in zip(x, y) if label == 1]
        negatives = [sample for sample, label in zip(x, y) if label == 0]
        for _ in range(self.trees):
            feature_index = rng.randint(0, feature_count - 1)
            pos_mean = sum(sample[feature_index] for sample in positives) / max(len(positives), 1)
            neg_mean = sum(sample[feature_index] for sample in negatives) / max(len(negatives), 1)
            threshold = (pos_mean + neg_mean) / 2
            polarity = 1.0 if pos_mean >= neg_mean else -1.0
            self.rules.append((feature_index, threshold, polarity))

    def predict_proba(self, x: list[list[float]]) -> list[float]:
        scores = []
        for sample in x:
            votes = 0.0
            for feature_index, threshold, polarity in self.rules:
                condition = sample[feature_index] >= threshold
                votes += 1.0 if (condition and polarity > 0) or ((not condition) and polarity < 0) else 0.0
            scores.append(votes / max(len(self.rules), 1))
        return scores


def metrics(y_true: list[int], probabilities: list[float], threshold: float = 0.5) -> dict[str, float]:
    predictions = [1 if score >= threshold else 0 for score in probabilities]
    tp = sum(1 for truth, pred in zip(y_true, predictions) if truth == pred == 1)
    tn = sum(1 for truth, pred in zip(y_true, predictions) if truth == pred == 0)
    fp = sum(1 for truth, pred in zip(y_true, predictions) if truth == 0 and pred == 1)
    fn = sum(1 for truth, pred in zip(y_true, predictions) if truth == 1 and pred == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / max(len(y_true), 1)
    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc_score(y_true, probabilities), 4),
    }


def roc_auc_score(y_true: list[int], scores: list[float]) -> float:
    pairs = sorted(zip(scores, y_true), key=lambda item: item[0], reverse=True)
    positives = sum(y_true)
    negatives = len(y_true) - positives
    if positives == 0 or negatives == 0:
        return 0.5
    tp = 0
    fp = 0
    prev_score = math.inf
    points = [(0.0, 0.0)]
    for score, truth in pairs:
        if score != prev_score:
            points.append((fp / negatives, tp / positives))
            prev_score = score
        if truth == 1:
            tp += 1
        else:
            fp += 1
    points.append((fp / negatives, tp / positives))
    auc = 0.0
    for (x1, y1), (x2, y2) in zip(points, points[1:]):
        auc += (x2 - x1) * (y1 + y2) / 2
    return auc


def benchmark(dataset_path: Path) -> dict[str, dict[str, float]]:
    records = load_records(dataset_path)
    phishing_records = [record for record in records if record["label"] in {"phishing", "benign"}]
    config = GenerationConfig(dataset_name="phishing", count=len(phishing_records), seed=1337)
    manager = DatasetManager(config)
    splits = manager.split_dataset(phishing_records)
    train_records = splits["train"]
    test_records = splits["test"]

    x_train = [vectorize(record) for record in train_records]
    y_train = [1 if record["label"] == "phishing" else 0 for record in train_records]
    x_test = [vectorize(record) for record in test_records]
    y_test = [1 if record["label"] == "phishing" else 0 for record in test_records]

    logistic = LogisticRegressionBaseline()
    logistic.fit(x_train, y_train)
    logistic_metrics = metrics(y_test, logistic.predict_proba(x_test), threshold=0.4)

    normalized_train, maxima = normalize(x_train)
    normalized_test = apply_normalization(x_test, maxima)
    forest = RandomThresholdForest()
    forest.fit(normalized_train, y_train)
    forest_metrics = metrics(y_test, forest.predict_proba(normalized_test), threshold=0.5)

    return {"logistic_regression": logistic_metrics, "random_threshold_forest": forest_metrics}


def main() -> None:
    results = benchmark(Path("data/output/phishing.json"))
    print(json.dumps({"models": results, "features": FEATURES}, indent=2))


if __name__ == "__main__":
    main()
