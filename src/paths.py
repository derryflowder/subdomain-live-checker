import random
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from src.models import PathFinding, ResultStatus, SubdomainResult

MAX_PATHS = 200
PATH_BODY_SAMPLE = 2048
DEFAULT_PATHS_TIMEOUT = 4.0
PATH_CONCURRENCY = 4
SOFT_404_LENGTH_TOLERANCE = 0.20
PATH_JITTER_MIN = 0.05
PATH_JITTER_MAX = 0.15

PATH_CHECKABLE_STATUSES: set[ResultStatus] = {
    ResultStatus.LIVE,
    ResultStatus.REDIRECT,
    ResultStatus.FORBIDDEN,
}

DEFAULT_PATHS: list[str] = [
    "admin",
    "login",
    "api",
    "dashboard",
    "console",
    ".git/config",
    ".env",
    ".well-known/security.txt",
    "robots.txt",
    "sitemap.xml",
    "phpinfo.php",
    "server-status",
    "actuator",
    "actuator/health",
    "swagger",
    "swagger-ui.html",
    "api/docs",
    "graphql",
    "wp-admin",
    "administrator",
    "backup.zip",
]

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; SubdomainLiveChecker/0.3.2; "
        "+https://github.com/)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TITLE_MAX = 200


def _extract_title(html: str) -> str | None:
    match = _TITLE_RE.search(html)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:_TITLE_MAX] or None


def _build_timeout(timeout: float) -> httpx.Timeout:
    return httpx.Timeout(
        connect=timeout,
        read=timeout,
        write=timeout,
        pool=timeout,
    )


def _jitter() -> None:
    delay = random.uniform(PATH_JITTER_MIN, PATH_JITTER_MAX)
    if delay > 0:
        time.sleep(delay)


def _fetch_path(
    client: httpx.Client,
    hostname: str,
    path: str,
) -> PathFinding | None:
    path_clean = path.strip().lstrip("/")
    if not path_clean:
        return None

    url = f"https://{hostname}/{path_clean}"

    try:
        with client.stream("GET", url) as response:
            code = response.status_code

            body = bytearray()
            try:
                for chunk in response.iter_bytes(chunk_size=PATH_BODY_SAMPLE):
                    body.extend(chunk)
                    if len(body) >= PATH_BODY_SAMPLE:
                        break
            except Exception:
                pass

            redirect = (
                response.headers.get("location")
                if 300 <= code < 400
                else None
            )

            length_header = response.headers.get("content-length")
            try:
                length_val = int(length_header) if length_header else len(body)
            except ValueError:
                length_val = len(body)

            title = None
            if body:
                try:
                    text = body.decode(
                        response.encoding or "utf-8", errors="replace"
                    )
                    title = _extract_title(text)
                except Exception:
                    title = None

            return PathFinding(
                path=path_clean,
                status_code=code,
                content_length=length_val,
                redirect_url=redirect,
                title=title,
            )
    except httpx.TimeoutException:
        return None
    except httpx.HTTPError:
        return None
    except Exception:
        return None


def _probe_soft_404(
    client: httpx.Client,
    hostname: str,
) -> PathFinding | None:
    _jitter()
    probe = f"_slc_probe_{uuid.uuid4().hex[:12]}"
    finding = _fetch_path(client, hostname, probe)
    if finding is None or finding.status_code is None:
        return None
    if 200 <= finding.status_code < 400:
        return finding
    return None


def _is_soft_404(
    baseline: PathFinding | None,
    finding: PathFinding | None,
) -> bool:
    if baseline is None or finding is None:
        return False
    if finding.status_code != baseline.status_code:
        return False

    if 300 <= finding.status_code < 400:
        return (
            finding.redirect_url is not None
            and baseline.redirect_url is not None
            and finding.redirect_url == baseline.redirect_url
        )

    if (
        baseline.title
        and finding.title
        and baseline.title == finding.title
    ):
        return True

    base = baseline.content_length
    cur = finding.content_length
    if base is not None and cur is not None:
        if base == 0 and cur == 0:
            return True
        if base > 0:
            delta = abs(cur - base) / base
            if delta <= SOFT_404_LENGTH_TOLERANCE:
                return True

    return False


def _is_interesting(
    finding: PathFinding,
    baseline: PathFinding | None = None,
) -> bool:
    code = finding.status_code
    if code is None or code == 404:
        return False
    if _is_soft_404(baseline, finding):
        return False
    return True


def _fetch_with_jitter(
    client: httpx.Client,
    hostname: str,
    path: str,
) -> PathFinding | None:
    _jitter()
    return _fetch_path(client, hostname, path)


def check_paths_for_result(
    result: SubdomainResult,
    paths: list[str],
    timeout: float = DEFAULT_PATHS_TIMEOUT,
    verify: bool = True,
) -> None:
    if not paths or result.is_removed:
        return

    trimmed = [p for p in (pp.strip() for pp in paths) if p][:MAX_PATHS]
    if not trimmed:
        return

    findings: list[PathFinding] = []

    try:
        with httpx.Client(
            timeout=_build_timeout(timeout),
            follow_redirects=False,
            headers=_HEADERS,
            verify=verify,
            limits=httpx.Limits(
                max_keepalive_connections=PATH_CONCURRENCY * 2,
                max_connections=PATH_CONCURRENCY * 2,
            ),
        ) as client:
            baseline = _probe_soft_404(client, result.hostname)

            with ThreadPoolExecutor(max_workers=PATH_CONCURRENCY) as pool:
                futures = {
                    pool.submit(
                        _fetch_with_jitter, client, result.hostname, path
                    ): path
                    for path in trimmed
                }
                for future in as_completed(futures):
                    try:
                        finding = future.result()
                    except Exception:
                        continue
                    if finding is None:
                        continue
                    if _is_interesting(finding, baseline):
                        findings.append(finding)
    except Exception:
        pass

    findings.sort(key=lambda f: f.path)
    result.findings = findings