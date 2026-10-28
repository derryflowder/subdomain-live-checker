from dataclasses import dataclass
from enum import StrEnum


class ResultStatus(StrEnum):
    LIVE = "live"
    REDIRECT = "redirect"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    ERROR = "error"


@dataclass(slots=True)
class SubdomainResult:
    hostname: str
    status: ResultStatus | None = None
    status_code: int | None = None
    response_time_ms: float | None = None
    final_url: str | None = None
    content_type: str | None = None
    server: str | None = None
    title: str | None = None
    error: str | None = None
