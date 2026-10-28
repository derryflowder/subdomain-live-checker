
import pytest

from src.gui.filtering import filter_results
from src.models import ResultStatus, SubdomainResult


@pytest.fixture
def sample_results():
    return [
        SubdomainResult(
            hostname="www.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
        ),
        SubdomainResult(
            hostname="api.example.com",
            status=ResultStatus.FORBIDDEN,
            status_code=403,
            is_new=True,
        ),
        SubdomainResult(
            hostname="old.example.com",
            status=ResultStatus.ERROR,
            is_removed=True,
        ),
        SubdomainResult(
            hostname="admin.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
            status_changed=True,
        ),
        SubdomainResult(
            hostname="shop.example.com",
            status=ResultStatus.ERROR,
            takeover="AWS S3 Bucket",
        ),
    ]


def test_all_returns_every_result(sample_results):
    assert filter_results(sample_results) == sample_results


def test_search_is_case_insensitive(sample_results):
    result = filter_results(sample_results, query="API")
    assert [item.hostname for item in result] == ["api.example.com"]


def test_live_excludes_removed(sample_results):
    result = filter_results(sample_results, filter_name="Live")
    assert {item.hostname for item in result} == {
        "www.example.com",
        "api.example.com",
        "admin.example.com",
    }


def test_issues_excludes_live_and_removed(sample_results):
    result = filter_results(sample_results, filter_name="Issues")
    assert {item.hostname for item in result} == {"shop.example.com"}


def test_new_filter(sample_results):
    result = filter_results(sample_results, filter_name="New")
    assert [item.hostname for item in result] == ["api.example.com"]


def test_changed_filter(sample_results):
    result = filter_results(sample_results, filter_name="Changed")
    assert [item.hostname for item in result] == ["admin.example.com"]


def test_removed_filter(sample_results):
    result = filter_results(sample_results, filter_name="Removed")
    assert [item.hostname for item in result] == ["old.example.com"]


def test_takeover_filter(sample_results):
    result = filter_results(sample_results, filter_name="Takeover")
    assert [item.hostname for item in result] == ["shop.example.com"]


def test_search_and_filter_work_together(sample_results):
    result = filter_results(
        sample_results,
        filter_name="Live",
        query="admin",
    )
    assert [item.hostname for item in result] == ["admin.example.com"]


def test_unknown_filter_raises_error(sample_results):
    with pytest.raises(ValueError, match="Unknown filter"):
        filter_results(sample_results, filter_name="Unknown")
