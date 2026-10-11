from types import SimpleNamespace
from unittest.mock import patch

import pandas as pd
import pytest

with patch("dash.register_page"):
    from dashboard.pages import overview


@pytest.fixture
def history():
    rows = [
        ("2026-10-10", "111", "east", "PASS"),
        ("2026-10-10", "222", "west", "FAIL"),
        ("2026-10-08", "111", "east", "FAIL"),
        ("2026-10-08", "222", "west", "PASS"),
        ("2026-10-08", "333", "older-only", "FAIL"),
        ("2026-09-01", "111", "east", "FAIL"),
    ]
    df = pd.DataFrame(
        rows, columns=["ASSESSMENT_TIME", "ACCOUNT_UID", "REGION", "STATUS"]
    )
    df["TIMESTAMP"] = pd.to_datetime(df["ASSESSMENT_TIME"])
    df["PROVIDER"] = "aws"
    df["SEVERITY"] = "high"
    df["SERVICE_NAME"] = "iam"
    df["CHECK_ID"] = "check1"
    df["CHECK_TITLE"] = "Synthetic check"
    return df


@pytest.fixture
def run_callback(monkeypatch, history):
    monkeypatch.setattr(overview, "data", history)
    monkeypatch.setattr(overview, "csv_files", [])
    monkeypatch.setattr(overview, "ctx", SimpleNamespace(triggered_id=None))
    # Table row layout is outside this chart regression; keep the real chart and cards.
    monkeypatch.setattr(overview, "generate_table", lambda *_args: None)

    def run(accounts=None, regions=None, assessment="2026-10-10"):
        return overview.filter_data(
            ["All"] if accounts is None else accounts,
            ["All"] if regions is None else regions,
            assessment,
            0,
            0,
            ["All"],
            ["All"],
            ["All"],
            100,
            ["All"],
            ["All"],
            "",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )

    return run


def chart_counts(result):
    figure = result[2][1].children[0].figure
    return {
        (pd.Timestamp(day).strftime("%Y-%m-%d"), trace.name): int(count)
        for trace in figure.data
        for day, count in zip(trace.x, trace.y)
    }


def test_chart_filters_selected_account_and_preserves_history(run_callback):
    counts = chart_counts(run_callback(accounts=["111 - AWS"]))
    assert counts[("2026-10-08", "FAIL")] == 1
    assert counts[("2026-10-10", "FAIL")] == 0
    assert counts[("2026-10-10", "PASS")] == 1
    assert all(day >= "2026-10-03" for day, _ in counts)


def test_chart_filters_region(run_callback):
    counts = chart_counts(run_callback(regions=["east"]))
    assert counts[("2026-10-08", "FAIL")] == 1
    assert counts[("2026-10-10", "FAIL")] == 0


@pytest.mark.parametrize("selection", [["All"], []])
def test_unrestricted_chart_keeps_older_accounts_and_regions(run_callback, selection):
    counts = chart_counts(run_callback(accounts=selection, regions=selection))
    assert counts[("2026-10-08", "FAIL")] == 2
    assert counts[("2026-10-08", "PASS")] == 1


def test_multiple_accounts_and_regions(run_callback):
    counts = chart_counts(
        run_callback(accounts=["111 - AWS", "222 - AWS"], regions=["east", "west"])
    )
    assert counts[("2026-10-08", "FAIL")] == 1
    assert counts[("2026-10-08", "PASS")] == 1


def test_empty_chart_for_unmatched_selection(run_callback):
    result = run_callback(accounts=["missing - AWS"])
    figure = result[2][1].children[0].figure
    assert all(not trace.values for trace in figure.data)


def test_callback_does_not_mutate_shared_data_or_selections(run_callback, history):
    before = history.copy(deep=True)
    accounts = ["All", "111 - AWS"]
    regions = ["All", "east"]
    first = chart_counts(run_callback(accounts=accounts, regions=regions))
    assert accounts == ["All", "111 - AWS"]
    assert regions == ["All", "east"]
    assert chart_counts(run_callback(accounts=accounts, regions=regions)) == first
    pd.testing.assert_frame_equal(history, before)


def test_name_only_account_input(run_callback, history, monkeypatch):
    names = history.rename(columns={"ACCOUNT_UID": "ACCOUNT_NAME"})
    names["PROVIDER"] = "gcp"
    monkeypatch.setattr(overview, "data", names)
    # Existing provider cards require ACCOUNT_UID independently of chart scope.
    monkeypatch.setattr(overview, "create_provider_card", lambda *_args: None)
    counts = chart_counts(run_callback(accounts=["111 - GCP"]))
    assert counts[("2026-10-08", "FAIL")] == 1
    assert counts[("2026-10-10", "PASS")] == 1


def test_both_account_columns(run_callback, history, monkeypatch):
    history["ACCOUNT_NAME"] = history["ACCOUNT_UID"].map(
        {"111": "one", "222": "two", "333": "three"}
    )
    counts = chart_counts(run_callback(accounts=["one - GCP"]))
    assert counts[("2026-10-08", "FAIL")] == 1
    assert counts[("2026-10-10", "PASS")] == 1


def test_assessment_changes_cards_but_preserves_chart_window(run_callback):
    latest = run_callback(accounts=["111 - AWS"])
    older = run_callback(accounts=["111 - AWS"], assessment="2026-10-08")
    assert chart_counts(latest) == chart_counts(older)
    latest_pie = latest[0][1].children[0].figure.data[0]
    older_pie = older[0][1].children[0].figure.data[0]
    assert list(latest_pie.labels) == ["PASS"]
    assert list(older_pie.labels) == ["FAIL"]
    assert latest[9] == "2026-10-10"
    assert older[9] == "2026-10-08"


def test_explicit_older_only_scope_keeps_history(run_callback):
    counts = chart_counts(run_callback(accounts=["333 - AWS"], regions=["older-only"]))
    assert counts[("2026-10-08", "FAIL")] == 1
    assert counts[("2026-10-10", "FAIL")] == 0


def test_table_keeps_selected_assessment_rows(run_callback, monkeypatch):
    rows = []
    monkeypatch.setattr(
        overview, "generate_table", lambda row, *_args: rows.append(row.copy())
    )
    run_callback(accounts=["111 - AWS"], assessment="2026-10-08")
    assert len(rows) == 1
    assert rows[0]["ASSESSMENT_TIME"] == "2026-10-08"
    assert rows[0]["STATUS"] == "FAIL"
    assert rows[0]["ACCOUNT_UID"] == "111 - AWS"
