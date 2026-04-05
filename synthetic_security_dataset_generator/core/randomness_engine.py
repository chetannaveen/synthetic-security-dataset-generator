from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable, Sequence, TypeVar

T = TypeVar("T")


@dataclass
class RandomnessEngine:
    seed: int

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def randint(self, start: int, end: int) -> int:
        return self._rng.randint(start, end)

    def uniform(self, start: float, end: float) -> float:
        return self._rng.uniform(start, end)

    def random(self) -> float:
        return self._rng.random()

    def choice(self, values: Sequence[T]) -> T:
        return self._rng.choice(list(values))

    def sample(self, values: Sequence[T], size: int) -> list[T]:
        return self._rng.sample(list(values), size)

    def weighted_choice(self, values: Sequence[T], weights: Sequence[float]) -> T:
        return self._rng.choices(list(values), weights=weights, k=1)[0]

    def shuffle(self, values: list[T]) -> list[T]:
        self._rng.shuffle(values)
        return values

    def token(self, alphabet: str, length: int) -> str:
        return "".join(self.choice(alphabet) for _ in range(length))

    def sequence_id(self, prefix: str) -> str:
        return f"{prefix}-{self.token('abcdef0123456789', 10)}"

    def cycle(self, values: Iterable[T]) -> T:
        values = list(values)
        return values[self.randint(0, len(values) - 1)]
