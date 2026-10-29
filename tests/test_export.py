import csv
from io import StringIO

from src.export import build_csv, build_html
from src.models import ResultStatus, SubdomainResult


def make_results() -> list[SubdomainResult]:
    return [
        SubdomainResult(
            hostname="www.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
            title="Welcome",
        ),
        SubdomainResult(
            hostname="new.example.com",
            status=ResultStatus.FORBIDDEN,
            status_code=403,
            is_new=True,
        ),
        SubdomainResult(
            hostname="old.example.com",
            is_removed=True,
            error="Was present in previous scan",
        ),
        SubdomainResult(
            hostname="takeover.example.com",
            status=ResultStatus.ERROR,
            takeover="Example cloud service",
        ),
    ]


def test_build_csv_contains_headers_and_result_flags() -> None:
    output = build_csv(make_results())
    rows = list(csv.reader(StringIO(output)))

    assert rows[0] == [
        "Hostname",
        "Status",
        "Code",
        "Time (ms)",
        "Title/Error",
        "Takeover Indicator",
        "New",
        "Changed",
        "Removed",
        "Final URL",
        "Content-Type",
        "Server",
        "Technologies",
        "Findings",
    ]

    assert rows[1][0] == "www.example.com"
    assert rows[1][2] == "200"
    assert rows[2][6] == "Yes"
    assert rows[3][8] == "Yes"
    assert rows[4][5] == "Example cloud service"


def test_build_csv_escapes_injection_payloads() -> None:
    result = SubdomainResult(
        hostname="evil.example.com",
        status=ResultStatus.LIVE,
        title="=cmd|' /C calc'!A0",
        takeover="+SUM(1,2)",
        server="-malicious",
    )

    rows = list(csv.reader(StringIO(build_csv([result]))))
    row = rows[1]

    assert row[4] == "=cmd|' /C calc'!A0".replace("=", "'=", 1) or row[4].startswith("'")
    assert row[5].startswith("'")
    assert row[11].startswith("'")


def test_build_html_contains_removed_and_takeover_rows() -> None:
    output = build_html(make_results(), "example.com")

    assert "Subdomain Scan Report: example.com" in output
    assert 'class="tr-removed"' in output
    assert "REMOVED" in output
    assert "old.example.com" in output
    assert "Potential Takeover: Example cloud service" in output


def test_build_html_escapes_untrusted_html() -> None:
    result = SubdomainResult(
        hostname="<script>alert(1)</script>.example.com",
        status=ResultStatus.LIVE,
        title="<img src=x onerror=alert(1)>",
    )

    output = build_html([result], "<script>domain</script>")

    assert "<script>" not in output
    assert "&lt;script&gt;" in output
    assert "&lt;img" in output


def test_build_csv_handles_empty_results() -> None:
    rows = list(csv.reader(StringIO(build_csv([]))))

    assert len(rows) == 1
    assert rows[0][0] == "Hostname"


def test_build_html_handles_empty_results() -> None:
    output = build_html([], "example.com")

    assert "<table>" in output
    assert "</table>" in output
    assert "example.com" in output