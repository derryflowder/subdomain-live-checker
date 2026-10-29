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
    "Technologies",
    "Findings",
]

_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value) -> str:
    text = "" if value is None else str(value)
    if text and text[0] in _CSV_INJECTION_PREFIXES:
        return "'" + text
    return text


def _tech_summary(result: SubdomainResult) -> str:
    if not result.technologies:
        return ""
    return ", ".join(t.display() for t in result.technologies)


def _findings_summary(result: SubdomainResult) -> str:
    if not result.findings:
        return ""
    return ", ".join(f"{f.path}:{f.status_code}" for f in result.findings)


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
                _safe_cell(_tech_summary(result)),
                _safe_cell(_findings_summary(result)),
            ]
        )

    return output.getvalue()


def _tech_html(result: SubdomainResult) -> str:
    if not result.technologies:
        return "-"
    parts = [html.escape(t.display()) for t in result.technologies]
    return ", ".join(parts)


def _findings_html(result: SubdomainResult) -> str:
    if not result.findings:
        return "-"
    items = []
    for f in result.findings:
        code = f.status_code if f.status_code is not None else "-"
        items.append(
            f"<span class=\"path-chip\">{html.escape(f.path)}"
            f"<span class=\"path-code\">{html.escape(str(code))}</span></span>"
        )
    return " ".join(items)


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
:root {{ color-scheme: dark; }}
body {{ background: #0a0a0a; color: #e5e5e5;
        font-family: -apple-system, "Segoe UI", sans-serif;
        padding: 32px; }}
h2 {{ color: #fafafa; font-weight: 700; }}
p {{ color: #737373; font-size: 13px; }}
table {{ border-collapse: collapse; width: 100%;
         margin-top: 20px; font-size: 13px; }}
th, td {{ padding: 10px 12px; text-align: left;
          border-bottom: 1px solid #1f1f1f; }}
th {{ background: #0f0f0f; color: #737373; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.5px;
      font-weight: 600; }}
.tr-new {{ background: rgba(16, 185, 129, 0.06); }}
.tr-changed {{ background: rgba(245, 158, 11, 0.06); }}
.tr-takeover {{ background: rgba(239, 68, 68, 0.08); }}
.tr-auth {{ background: rgba(96, 165, 250, 0.05); }}
.tr-removed {{ color: #6b6b6b; }}
.path-chip {{ display: inline-block; background: #141414;
              border: 1px solid #262626; border-radius: 6px;
              padding: 2px 8px; margin: 2px; font-size: 11px; }}
.path-code {{ margin-left: 6px; color: #a3a3a3; }}
</style>
</head>
<body>
<h2>Subdomain Scan Report: {safe_domain}</h2>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<table>
<tr>
<th>Hostname</th><th>Status</th><th>Code</th><th>Tech</th>
<th>Findings</th><th>Title/Error</th><th>Final URL</th><th>Removed</th>
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
            safe_title = f"⚠️ Potential Takeover: {html.escape(result.takeover)}"

        code_value = (
            html.escape(str(result.status_code))
            if result.status_code is not None
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
        tech_value = _tech_html(result)
        findings_value = _findings_html(result)

        output.write(
            f"""
<tr class="{html.escape(row_class)}">
<td>{safe_hostname}</td>
<td>{safe_status}</td>
<td>{code_value}</td>
<td>{tech_value}</td>
<td>{findings_value}</td>
<td>{safe_title}</td>
<td>{final_url_value}</td>
<td>{removed_value}</td>
</tr>
"""
        )

    output.write("</table></body></html>")
    return output.getvalue()