from src.models import PathFinding, ResultStatus, SubdomainResult
from src.paths import (
    MAX_PATHS,
    _is_interesting,
    _is_soft_404,
    check_paths_for_result,
)


def test_is_interesting_ignores_404():
    finding = PathFinding(path="x", status_code=404)
    assert _is_interesting(finding) is False


def test_is_interesting_ignores_none_status():
    finding = PathFinding(path="x", status_code=None)
    assert _is_interesting(finding) is False


def test_is_interesting_accepts_200():
    finding = PathFinding(path="x", status_code=200, content_length=100)
    assert _is_interesting(finding) is True


def test_is_interesting_accepts_403():
    finding = PathFinding(path="x", status_code=403, content_length=50)
    assert _is_interesting(finding) is True


def test_soft_404_same_title_and_length():
    baseline = PathFinding(
        path="_probe", status_code=200, content_length=1000, title="Home"
    )
    finding = PathFinding(
        path="admin", status_code=200, content_length=1000, title="Home"
    )
    assert _is_soft_404(baseline, finding) is True


def test_soft_404_close_length_without_title():
    baseline = PathFinding(path="_probe", status_code=200, content_length=1000)
    finding = PathFinding(path="admin", status_code=200, content_length=1050)
    assert _is_soft_404(baseline, finding) is True


def test_real_finding_not_soft_404():
    baseline = PathFinding(
        path="_probe", status_code=200, content_length=1000, title="Home"
    )
    finding = PathFinding(
        path="admin", status_code=200, content_length=5000, title="Admin"
    )
    assert _is_soft_404(baseline, finding) is False


def test_different_status_not_soft_404():
    baseline = PathFinding(path="_probe", status_code=200, content_length=1000)
    finding = PathFinding(path="admin", status_code=403)
    assert _is_soft_404(baseline, finding) is False


def test_soft_404_none_baseline_returns_false():
    finding = PathFinding(path="admin", status_code=200, content_length=500)
    assert _is_soft_404(None, finding) is False


def test_check_paths_skips_removed(monkeypatch):
    monkeypatch.setattr("src.paths._jitter", lambda: None)
    called = []

    def fake_fetch(client, hostname, path):
        called.append(path)
        return PathFinding(path=path, status_code=200)

    monkeypatch.setattr("src.paths._fetch_path", fake_fetch)

    result = SubdomainResult(hostname="old.example.com", is_removed=True)
    check_paths_for_result(result, ["admin", "login"])

    assert called == []
    assert result.findings == []


def test_check_paths_respects_max_paths(monkeypatch):
    monkeypatch.setattr("src.paths._jitter", lambda: None)
    called = []

    def fake_fetch(client, hostname, path):
        called.append(path)
        return PathFinding(path=path, status_code=404)

    monkeypatch.setattr("src.paths._fetch_path", fake_fetch)

    result = SubdomainResult(hostname="example.com", status=ResultStatus.LIVE)
    paths = [f"path{i}" for i in range(MAX_PATHS + 50)]
    check_paths_for_result(result, paths)

    real_calls = [c for c in called if not c.startswith("_slc_probe_")]
    assert len(real_calls) == MAX_PATHS


def test_check_paths_filters_soft_404(monkeypatch):
    monkeypatch.setattr("src.paths._jitter", lambda: None)

    def fake_fetch(client, hostname, path):
        return PathFinding(
            path=path, status_code=200, content_length=1000, title="Home"
        )

    monkeypatch.setattr("src.paths._fetch_path", fake_fetch)

    result = SubdomainResult(hostname="spa.example.com", status=ResultStatus.LIVE)
    check_paths_for_result(result, ["admin", "login", "api"])

    assert result.findings == []


def test_check_paths_keeps_real_findings(monkeypatch):
    monkeypatch.setattr("src.paths._jitter", lambda: None)

    def fake_fetch(client, hostname, path):
        if path.startswith("_slc_probe_"):
            return PathFinding(
                path=path, status_code=200, content_length=1000, title="Home"
            )
        if path == "admin":
            return PathFinding(
                path=path, status_code=200, content_length=5000, title="Admin"
            )
        return PathFinding(path=path, status_code=404)

    monkeypatch.setattr("src.paths._fetch_path", fake_fetch)

    result = SubdomainResult(hostname="example.com", status=ResultStatus.LIVE)
    check_paths_for_result(result, ["admin", "login"])

    assert len(result.findings) == 1
    assert result.findings[0].path == "admin"


def test_check_paths_sorts_findings(monkeypatch):
    monkeypatch.setattr("src.paths._jitter", lambda: None)

    def fake_fetch(client, hostname, path):
        if path.startswith("_slc_probe_"):
            return None
        if path in ("zeta", "alpha", "mu"):
            return PathFinding(
                path=path, status_code=200, content_length=5000, title=path
            )
        return PathFinding(path=path, status_code=404)

    monkeypatch.setattr("src.paths._fetch_path", fake_fetch)

    result = SubdomainResult(hostname="example.com", status=ResultStatus.LIVE)
    check_paths_for_result(result, ["zeta", "alpha", "mu"])

    assert [f.path for f in result.findings] == ["alpha", "mu", "zeta"]


def test_check_paths_empty_paths_does_nothing(monkeypatch):
    monkeypatch.setattr("src.paths._jitter", lambda: None)
    result = SubdomainResult(hostname="example.com", status=ResultStatus.LIVE)
    check_paths_for_result(result, [])
    assert result.findings == []