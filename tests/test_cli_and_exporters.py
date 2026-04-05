from pathlib import Path

from synthetic_security_dataset_generator.cli.main import generate_one


class Args:
    dataset = "phishing"
    count = 10
    malicious_ratio = 0.4
    seed = 9
    attack_type = []
    format = "json"
    output_dir = "tests/tmp_output"
    size = None


def test_generate_one_writes_json(tmp_path: Path):
    args = Args()
    args.output_dir = str(tmp_path)
    result = generate_one("phishing", args)
    output = Path(result["output"])
    assert output.exists()
    assert result["summary"]["records"] == 10
