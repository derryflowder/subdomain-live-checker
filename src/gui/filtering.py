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
}


def filter_results(
    results: list[SubdomainResult],
    filter_name: str = "All",
    query: str = "",
) -> list[SubdomainResult]:
    """Filter scan results by category and hostname."""
    if filter_name not in VALID_FILTERS:
        raise ValueError(f"Unknown filter: {filter_name}")

    normalized_query = query.strip().casefold()
    filtered = []

    for result in results:
        if normalized_query not in result.hostname.casefold():
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

        filtered.append(result)

    return filtered