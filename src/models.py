from dataclasses import dataclass, field
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
class PathFinding:
    path: str
    status_code: int | None = None
    content_length: int | None = None
    redirect_url: str | None = None
    title: str | None = None


@dataclass(slots=True)
class TechDetection:
    name: str
    version: str | None = None
    category: str = "other"

    def display(self) -> str:
        return f"{self.name}/{self.version}" if self.version else self.name


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

    takeover: str | None = None
    is_new: bool = False
    status_changed: bool = False
    is_removed: bool = False

    technologies: list[TechDetection] = field(default_factory=list)
    findings: list[PathFinding] = field(default_factory=list)