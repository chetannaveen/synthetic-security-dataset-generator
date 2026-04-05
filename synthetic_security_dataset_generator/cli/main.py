from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.dataset_generators.code_vuln_generator import VulnerableCodeGenerator
from synthetic_security_dataset_generator.dataset_generators.log_generator import AttackLogGenerator
from synthetic_security_dataset_generator.dataset_generators.phishing_generator import PhishingURLGenerator
from synthetic_security_dataset_generator.dataset_generators.user_behavior_generator import UserBehaviorGenerator
from synthetic_security_dataset_generator.exporters.csv_exporter import CsvExporter
from synthetic_security_dataset_generator.exporters.json_exporter import JsonExporter


GENERATOR_REGISTRY = {
    "phishing": PhishingURLGenerator,
    "logs": AttackLogGenerator,
    "code": VulnerableCodeGenerator,
    "user_behavior": UserBehaviorGenerator,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synthetic Security Dataset Generator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="Generate synthetic datasets")
    generate.add_argument("dataset", choices=[*GENERATOR_REGISTRY.keys(), "all"])
    generate.add_argument("--count", type=int, default=100)
    generate.add_argument("--malicious-ratio", type=float, default=0.35)
    generate.add_argument("--seed", type=int, default=1337)
    generate.add_argument("--attack-type", action="append", default=[])
    generate.add_argument("--format", choices=["json", "csv"], default="json")
    generate.add_argument("--output-dir", default="data/output")
    generate.add_argument("--size", choices=["small", "medium", "large"], default=None)
    return parser


def resolve_count(args: argparse.Namespace) -> int:
    sizes = {"small": 100, "medium": 1000, "large": 5000}
    return sizes[args.size] if args.size else args.count


def exporter_for(fmt: str) -> JsonExporter | CsvExporter:
    return JsonExporter() if fmt == "json" else CsvExporter()


def generate_one(dataset: str, args: argparse.Namespace) -> dict[str, Any]:
    config = GenerationConfig(
        dataset_name=dataset,
        count=resolve_count(args),
        malicious_ratio=args.malicious_ratio,
        seed=args.seed,
        attack_types=args.attack_type,
        output_dir=Path(args.output_dir),
        format=args.format,
    )
    generator = GENERATOR_REGISTRY[dataset](config)
    records = generator.generate_dataset()
    destination = config.output_dir / f"{dataset}.{config.format}"
    exporter_for(config.format).export(records, destination)
    return {"output": str(destination), "summary": generator.summarize(records)}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    datasets = list(GENERATOR_REGISTRY) if args.dataset == "all" else [args.dataset]
    for dataset in datasets:
        result = generate_one(dataset, args)
        print(f"[{dataset}] wrote {result['output']}")
        print(result["summary"])


if __name__ == "__main__":
    main()
