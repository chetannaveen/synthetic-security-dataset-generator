from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from typing import Any

from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.core.labeling_engine import LabelingEngine
from synthetic_security_dataset_generator.core.randomness_engine import RandomnessEngine


class BaseGenerator(ABC):
    dataset_name: str

    def __init__(self, config: GenerationConfig) -> None:
        self.config = config
        self.random = RandomnessEngine(config.seed)
        self.labeling = LabelingEngine()

    @abstractmethod
    def generate_record(self, malicious: bool | None = None, attack_type: str | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def build_balance_plan(self) -> list[bool | None]:
        malicious_count = int(self.config.count * self.config.malicious_ratio)
        neutral_count = self.config.count - malicious_count
        plan: list[bool | None] = [True] * malicious_count + [False] * neutral_count
        return self.random.shuffle(plan)

    def generate_dataset(self) -> list[dict[str, Any]]:
        dataset = [
            self.generate_record(malicious=flag, attack_type=self.pick_attack_type(flag))
            for flag in self.build_balance_plan()
        ]
        return dataset

    def pick_attack_type(self, malicious: bool | None) -> str | None:
        if not malicious or not self.config.attack_types:
            return None
        return self.random.choice(self.config.attack_types)

    def summarize(self, dataset: list[dict[str, Any]]) -> dict[str, Any]:
        labels = Counter(item.get("label", "unknown") for item in dataset)
        categories = Counter(item.get("category", "unknown") for item in dataset)
        return {
            "dataset": self.dataset_name,
            "records": len(dataset),
            "labels": dict(labels),
            "categories": dict(categories),
            "seed": self.config.seed,
        }
