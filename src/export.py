import csv
import html
from datetime import datetime
from io import StringIO

from src.models import SubdomainResult

CSV_HEADERS = [
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
]

_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value) -> str:
    """Prevent CSV formula injection (Excel / LibreOffice / Google Sheets)."""
    text = "" if value is None else str(value)
    if text and text[0] in _CSV_INJECTION_PREFIXES:
        return "'" + text
    return text


def build_csv(results: list[SubdomainResult]) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_HEADERS)

    for result in results:
        writer.writerow(
            [
                result.hostname,
                result.status.value if result.status else "",
                result.status_code if result.status_code is not None else "",
                (
                    result.response_time_ms
                    if result.response_time_ms is not None
                    else ""
                ),
                _safe_cell(result.title or result.error or ""),
                _safe_cell(result.takeover or ""),
                "Yes" if result.is_new else "No",
                "Yes" if result.status_changed else "No",
                "Yes" if result.is_removed else "No",
                _safe_cell(result.final_url or ""),
                _safe_cell(result.content_type or ""),
                _safe_cell(result.server or ""),
            ]
        )

    return output.getvalue()


def build_html(results: list[SubdomainResult], domain: str) -> str:
    safe_domain = html.escape(domain)
    output = StringIO()

    output.write(
        f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Report: {safe_domain}</title>
<style>
body {{ background: #0b0f14; color: #e2e8f0; font-family: sans-serif; padding: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ border: 1px solid #202936; padding: 8px; text-align: left; }}
th {{ background: #111720; color: #8996a8; }}
.tr-new {{ background: #064e3b; color: #d1fae5; }}
.tr-changed {{ background: #78350f; color: #fef3c7; }}
.tr-takeover {{ background: #7f1d1d; color: #fecaca; }}
.tr-auth {{ background: #312e81; color: #e0e7ff; }}
.tr-removed {{ background: #374151; color: #d1d5db; }}
</style>
</head>
<body>
<h2>Subdomain Scan Report: {safe_domain}</h2>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<table>
<tr>
<th>Hostname</th><th>Status</th><th>Code</th>
<th>Time</th><th>Title/Error</th><th>Final URL</th><th>Removed</th>
</tr>
"""
    )

    for result in results:
        row_class = ""

        if result.is_removed:
            row_class = "tr-removed"
        elif result.takeover:
            row_class = "tr-takeover"
        elif result.is_new:
            row_class = "tr-new"
        elif result.status_changed:
            row_class = "tr-changed"
        elif result.status_code in (401, 403):
            row_class = "tr-auth"

        safe_hostname = html.escape(result.hostname)
        safe_title = html.escape(result.title or result.error or "-")

        if result.takeover:
            safe_title = (
                f"⚠️ Potential Takeover: {html.escape(result.takeover)}"
            )

        code_value = (
            html.escape(str(result.status_code))
            if result.status_code is not None
            else "-"
        )
        time_value = (
            html.escape(f"{result.response_time_ms} ms")
            if result.response_time_ms is not None
            else "-"
        )
        status_value = (
            "REMOVED"
            if result.is_removed
            else result.status.value if result.status else "-"
        )
        safe_status = html.escape(status_value)
        removed_value = "Yes" if result.is_removed else "No"
        final_url_value = html.escape(result.final_url or "-")

        output.write(
            f"""
<tr class="{html.escape(row_class)}">
<td>{safe_hostname}</td>
<td>{safe_status}</td>
<td>{code_value}</td>
<td>{time_value}</td>
<td>{safe_title}</td>
<td>{final_url_value}</td>
<td>{removed_value}</td>
</tr>
"""
        )

    output.write("</table></body></html>")
    return output.getvalue()