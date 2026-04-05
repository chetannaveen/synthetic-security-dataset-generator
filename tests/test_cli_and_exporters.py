from pathlib import Path

from synthetic_security_dataset_generator.cli.main import (
    export_graph,
    generate_one,
    report_dataset,
    split_dataset,
    validate_dataset,
)


class Args:
    dataset = "phishing"
    count = 18
    malicious_ratio = 0.4
    seed = 9
    attack_type = []
    format = "json"
    output_dir = "tests/tmp_output"
    size = None
    flatten = False
    stream = False
    dataset_version = "v0.2.0"
    code_mode = "classification"
    chunk_size = 10
    ml_format = False
    progress = False
    graph_export = True


def test_generate_one_writes_json_and_manifest(tmp_path: Path):
    args = Args()
    args.output_dir = str(tmp_path)
    result = generate_one("phishing", args)
    output = Path(result["output"])
    assert output.exists()
    assert result["summary"]["records"] == 18
    assert Path(result["manifest"]).exists()
    assert (tmp_path / "phishing_graph.csv").exists()


def test_split_validate_report_and_graph(tmp_path: Path):
    args = Args()
    args.output_dir = str(tmp_path)
    generate_one("phishing", args)

    class SplitArgs:
        dataset = "phishing"
        input = None
        input_format = "json"
        output_format = "json"
        output_dir = str(tmp_path)
        train = 0.7
        val = 0.15
        test = 0.15
        seed = 9
        flatten = False

    split_result = split_dataset("phishing", SplitArgs())
    assert Path(split_result["manifest"]).exists()
    assert Path(split_result["outputs"]["train"]).exists()

    class ValidateArgs:
        dataset = "phishing"
        input = None
        input_format = "json"
        output_dir = str(tmp_path)

    validation = validate_dataset("phishing", ValidateArgs())
    assert validation["stats"]["record_count"] == 18
    assert validation["quality_score"] > 0

    class ReportArgs:
        dataset = "phishing"
        input = None
        input_format = "json"
        output_dir = str(tmp_path)
        report_format = "json"

    report = report_dataset("phishing", ReportArgs())
    assert Path(report["output"]).exists()

    class GraphArgs:
        dataset = "phishing"
        input = None
        input_format = "json"
        output_dir = str(tmp_path)

    graph = export_graph("phishing", GraphArgs())
    assert graph["edges"] > 0
