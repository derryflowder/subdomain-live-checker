from src.models import ResultStatus, SubdomainResult

LIVE_STATUSES = {
    ResultStatus.LIVE,
    ResultStatus.REDIRECT,
    ResultStatus.FORBIDDEN,
}

VALID_FILTERS = {
    "All",
    "Live",
    "Issues",
    "New",
    "Changed",
    "Removed",
    "Takeover",
    "With findings",
}


def filter_results(
    results: list[SubdomainResult],
    filter_name: str = "All",
    query: str = "",
) -> list[SubdomainResult]:
    if filter_name not in VALID_FILTERS:
        raise ValueError(f"Unknown filter: {filter_name}")

    normalized_query = query.strip().casefold()
    filtered = []

    for result in results:
        if normalized_query:
            haystack = " ".join(
                filter(
                    None,
                    [
                        result.hostname,
                        result.title or "",
                        result.error or "",
                        " ".join(t.display() for t in result.technologies),
                        " ".join(f.path for f in result.findings),
                    ],
                )
            ).casefold()
            if normalized_query not in haystack:
                continue

        if filter_name == "Live":
            if result.is_removed or result.status not in LIVE_STATUSES:
                continue
        elif filter_name == "Issues":
            if result.is_removed or result.status in LIVE_STATUSES:
                continue
        elif filter_name == "New" and not result.is_new:
            continue
        elif filter_name == "Changed" and not result.status_changed:
            continue
        elif filter_name == "Removed" and not result.is_removed:
            continue
        elif filter_name == "Takeover" and not result.takeover:
            continue
        elif filter_name == "With findings" and not result.findings:
            continue

        filtered.append(result)

    return filtered