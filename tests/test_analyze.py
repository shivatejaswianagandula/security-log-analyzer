from pathlib import Path
from src.analyze import parse_log_line, analyze_logs

def test_parse_log_line_extracts_fields():
    line = "2026-01-01 10:01:11 user=alex ip=10.0.0.5 status=FAIL"
    data = parse_log_line(line)
    assert data["user"] == "alex"
    assert data["ip"] == "10.0.0.5"
    assert data["status"] == "FAIL"

def test_analyze_logs_counts_failures_and_unique_users(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join([
            "2026-01-01 10:01:11 user=alex ip=10.0.0.5 status=FAIL",
            "2026-01-01 10:01:30 user=alex ip=10.0.0.5 status=FAIL",
            "2026-01-01 10:02:05 user=alex ip=10.0.0.5 status=SUCCESS",
            "2026-01-01 12:00:01 user=john ip=10.0.0.9 status=FAIL",
            "2026-01-01 12:00:10 user=rita ip=10.0.0.9 status=FAIL",
        ])
    )

    failed_count, ip_to_users = analyze_logs(str(log_file))

    assert failed_count[("alex", "10.0.0.5")] == 2
    assert failed_count[("john", "10.0.0.9")] == 1
    assert failed_count[("rita", "10.0.0.9")] == 1

    assert ip_to_users["10.0.0.5"] == {"alex"}
    assert ip_to_users["10.0.0.9"] == {"john", "rita"}
