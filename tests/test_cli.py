import io
import json
from pathlib import Path

import pytest

from sg_exposure_check.cli import main

EX = Path(__file__).resolve().parent.parent / "examples"
ARGS = ["-i", str(EX / "security-groups.json"), "-i", str(EX / "network-interfaces.json")]


def test_example_text(capsys):
    assert main(ARGS) == 1
    out = capsys.readouterr().out
    assert "Checked 7 security groups: 9 internet-open rules in 5 groups" in out
    assert "[CRITICAL] sg-0a1b2c3d4e5f00005 (batch-workers) tcp/0-65535 from ::/0" in out
    assert "-> rds RDSNetworkInterface" in out
    assert "internal-api" not in out and "orders-lambda" not in out


def test_example_json_and_filters(capsys):
    assert main(ARGS + ["-f", "json", "--min-severity", "medium"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0}
    assert [f["group_name"] for f in doc["findings"]] == ["batch-workers", "bastion-ssh", "orders-db"]


def test_fail_on(capsys):
    assert main(ARGS + ["--fail-on", "never"]) == 0
    assert main(ARGS + ["--min-severity", "critical", "--fail-on", "critical"]) == 1
    assert main(["-i", str(EX / "security-groups.json"), "-i", str(EX / "network-interfaces.json"),
                 "--min-severity", "medium", "--fail-on", "high", "--ports-file", str(EX / "ports.yaml")]) == 1


def test_custom_port_flag(capsys):
    main(ARGS + ["--port", "8080=Jenkins", "-f", "json"])
    doc = json.loads(capsys.readouterr().out)
    jenkins = [f for f in doc["findings"] if f["ports"] == "8080"][0]
    assert jenkins["services"] == ["Jenkins (8080)"] and jenkins["severity"] == "medium"


def test_sg_only_warns(capsys):
    assert main(["-i", str(EX / "security-groups.json")]) == 1
    captured = capsys.readouterr()
    assert "no NetworkInterfaces" in captured.err
    assert "attachments unknown" in captured.out


def test_stdin_and_clean(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"SecurityGroups": [{"GroupId": "sg-1"}], "NetworkInterfaces": []})))
    assert main(["-i", "-"]) == 0
    assert "no ingress open" in capsys.readouterr().out


def test_errors(tmp_path, capsys):
    assert main(["-i", str(tmp_path / "missing.json")]) == 2
    with pytest.raises(SystemExit):
        main(["-i", "x", "--port", "http"])
