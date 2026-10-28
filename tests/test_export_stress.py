import csv
import time
from io import StringIO

from src.export import build_csv, build_html
from src.models import ResultStatus, SubdomainResult


def test_export_100000_results_stress():
    count = 100_000
    results = [
        SubdomainResult(
            hostname=f"host-{i}.example.com",
            status=ResultStatus.LIVE if i % 2 == 0 else ResultStatus.FORBIDDEN,
            status_code=200 if i % 2 == 0 else 403,
            title=f"Test page {i}",
            final_url=f"https://host-{i}.example.com/",
            is_new=i % 10 == 0,
        )
        for i in range(count)
    ]

    start = time.perf_counter()
    csv_output = build_csv(results)
    csv_seconds = time.perf_counter() - start

    start = time.perf_counter()
    html_output = build_html(results, "example.com")
    html_seconds = time.perf_counter() - start

    csv_rows = list(csv.reader(StringIO(csv_output)))
    assert len(csv_rows) == count + 1
    assert csv_rows[1][0] == "host-0.example.com"
    assert csv_rows[-1][0] == f"host-{count - 1}.example.com"

    assert html_output.count("<tr class=") == count
    assert "host-0.example.com" in html_output
    assert f"host-{count - 1}.example.com" in html_output
    assert "</html>" in html_output

    print(f"\nStress test: {count:,} results")
    print(f"CSV:  {csv_seconds:.3f}s, {len(csv_output):,} characters")
    print(f"HTML: {html_seconds:.3f}s, {len(html_output):,} characters")


