from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LabelDecision:
    label: str
    category: str
    explanation: str
    features: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "category": self.category,
            "explanation": self.explanation,
            "features": self.features,
            "metadata": self.metadata,
        }


class LabelingEngine:
    def attach(self, record: dict[str, Any], decision: LabelDecision) -> dict[str, Any]:
        enriched = dict(record)
        enriched.update(decision.as_dict())
        return enriched
