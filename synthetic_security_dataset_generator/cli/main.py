from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from synthetic_security_dataset_generator.core.config import GenerationConfig
from synthetic_security_dataset_generator.core.dataset_manager import DatasetManager
from synthetic_security_dataset_generator.core.validator import DatasetValidator
from synthetic_security_dataset_generator.dataset_generators.code_vuln_generator import VulnerableCodeGenerator
from synthetic_security_dataset_generator.dataset_generators.log_generator import AttackLogGenerator
from synthetic_security_dataset_generator.dataset_generators.phishing_generator import PhishingURLGenerator
from synthetic_security_dataset_generator.dataset_generators.user_behavior_generator import UserBehaviorGenerator
from synthetic_security_dataset_generator.exporters.csv_exporter import CsvExporter
from synthetic_security_dataset_generator.exporters.json_exporter import JsonExporter
from synthetic_security_dataset_generator.exporters.parquet_exporter import ParquetExporter
from synthetic_security_dataset_generator.utils.record_utils import load_records


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
    generate.add_argument("--format", choices=["json", "csv", "parquet"], default="json")
    generate.add_argument("--output-dir", default="data/output")
    generate.add_argument("--size", choices=["small", "medium", "large"], default=None)
    generate.add_argument("--flatten", action="store_true")
    generate.add_argument("--stream", action="store_true")
    generate.add_argument("--dataset-version", default="v0.2.0")
    generate.add_argument("--code-mode", choices=["classification", "localization"], default="classification")

    validate = subparsers.add_parser("validate", help="Validate an existing dataset")
    validate.add_argument("dataset", choices=GENERATOR_REGISTRY.keys())
    validate.add_argument("--input", default=None)
    validate.add_argument("--input-format", choices=["json", "csv"], default="json")
    validate.add_argument("--output-dir", default="data/output")

    split = subparsers.add_parser("split", help="Split an existing dataset into train/validation/test")
    split.add_argument("dataset", choices=GENERATOR_REGISTRY.keys())
    split.add_argument("--input", default=None)
    split.add_argument("--input-format", choices=["json", "csv"], default="json")
    split.add_argument("--output-format", choices=["json", "csv", "parquet"], default="json")
    split.add_argument("--output-dir", default="data/output")
    split.add_argument("--train", type=float, default=0.7)
    split.add_argument("--val", type=float, default=0.15)
    split.add_argument("--test", type=float, default=0.15)
    split.add_argument("--seed", type=int, default=1337)
    split.add_argument("--flatten", action="store_true")

    summarize = subparsers.add_parser("summarize", help="Summarize an existing dataset")
    summarize.add_argument("dataset", choices=GENERATOR_REGISTRY.keys())
    summarize.add_argument("--input", default=None)
    summarize.add_argument("--input-format", choices=["json", "csv"], default="json")
    summarize.add_argument("--output-dir", default="data/output")
    return parser


def resolve_count(args: argparse.Namespace) -> int:
    sizes = {"small": 100, "medium": 1000, "large": 5000}
    return sizes[args.size] if args.size else args.count


def exporter_for(fmt: str) -> JsonExporter | CsvExporter | ParquetExporter:
    if fmt == "json":
        return JsonExporter()
    if fmt == "csv":
        return CsvExporter()
    return ParquetExporter()


def generate_one(dataset: str, args: argparse.Namespace) -> dict[str, Any]:
    config = GenerationConfig(
        dataset_name=dataset,
        count=resolve_count(args),
        malicious_ratio=args.malicious_ratio,
        seed=args.seed,
        attack_types=args.attack_type,
        output_dir=Path(args.output_dir),
        format=args.format,
        dataset_version=args.dataset_version,
        flatten_nested=args.flatten,
        stream_write=args.stream,
        code_dataset_mode=args.code_mode,
    )
    generator = GENERATOR_REGISTRY[dataset](config)
    records = generator.generate_dataset()
    destination = config.output_dir / f"{dataset}.{config.format}"
    exporter_for(config.format).export(
        records,
        destination,
        flatten_nested=config.flatten_nested,
        stream_write=config.stream_write,
    )
    manager = DatasetManager(config)
    manifest = manager.create_manifest(dataset, records, generator.summarize(records)["feature_list"], {"full": str(destination)})
    manifest_path = manager.write_manifest(manifest, config.output_dir / f"{dataset}_manifest.json")
    return {"output": str(destination), "manifest": str(manifest_path), "summary": generator.summarize(records)}


def resolve_input_path(dataset: str, args: argparse.Namespace) -> Path:
    if args.input:
        return Path(args.input)
    input_format = getattr(args, "input_format", getattr(args, "format", "json"))
    return Path(args.output_dir) / f"{dataset}.{input_format}"


def validate_dataset(dataset: str, args: argparse.Namespace) -> dict[str, Any]:
    records = load_records(resolve_input_path(dataset, args))
    result = DatasetValidator().validate(records)
    return {"dataset": dataset, **result}


def split_dataset(dataset: str, args: argparse.Namespace) -> dict[str, Any]:
    path = resolve_input_path(dataset, args)
    records = load_records(path)
    config = GenerationConfig(
        dataset_name=dataset,
        count=len(records),
        seed=args.seed,
        output_dir=Path(args.output_dir),
        format=args.output_format,
        train_ratio=args.train,
        val_ratio=args.val,
        test_ratio=args.test,
        flatten_nested=args.flatten,
    )
    manager = DatasetManager(config)
    splits = manager.split_dataset(records)
    base_path = Path(args.output_dir) / dataset
    outputs = manager.write_split_files(splits, exporter_for(args.output_format), base_path, args.output_format)
    manifest = manager.create_manifest(dataset, records, manager.collect_feature_list(records), outputs)
    manifest_path = manager.write_manifest(manifest, Path(args.output_dir) / f"{dataset}_split_manifest.json")
    return {"outputs": outputs, "manifest": str(manifest_path)}


def summarize_dataset(dataset: str, args: argparse.Namespace) -> dict[str, Any]:
    path = resolve_input_path(dataset, args)
    records = load_records(path)
    input_format = getattr(args, "input_format", "json")
    config = GenerationConfig(dataset_name=dataset, count=len(records), output_dir=Path(args.output_dir), format=input_format)
    return DatasetManager(config).summarize_dataset(records)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "generate":
        datasets = list(GENERATOR_REGISTRY) if args.dataset == "all" else [args.dataset]
        for dataset in datasets:
            result = generate_one(dataset, args)
            print(f"[{dataset}] wrote {result['output']}")
            print(f"[{dataset}] manifest {result['manifest']}")
            print(result["summary"])
    elif args.command == "validate":
        print(validate_dataset(args.dataset, args))
    elif args.command == "split":
        print(split_dataset(args.dataset, args))
    elif args.command == "summarize":
        print(summarize_dataset(args.dataset, args))


if __name__ == "__main__":
    main()
