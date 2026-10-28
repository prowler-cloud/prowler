import csv
from io import StringIO
from types import SimpleNamespace

import pandas as pd
import pytest

from dashboard.pages import overview
from dashboard.pages.overview import _sanitize_csv_export


def _df():
    return pd.DataFrame(
        {
            "PROVIDER": ["aws"],
            "CHECKID": ["s3_bucket_public_access"],
            "RESOURCE_TAGS": ["=1+1"],
            "STATUS": ["FAIL"],
            "SEVERITY": [4.5],
        }
    )


class TestSanitizeCsvExport:
    def test_formula_initiators_are_neutralised(self):
        """Cells starting with =, +, -, @, tab or CR get a leading single quote."""
        for initiator in ("=", "+", "-", "@", "\t", "\r"):
            df = pd.DataFrame({"VALUE": [f"{initiator}cmd"]})
            result = _sanitize_csv_export(df)
            assert result["VALUE"].iloc[0] == f"'{initiator}cmd"

    def test_tag_value_formula_is_neutralised(self):
        """The reported case: a resource tag of '=1+1' must not reach the CSV verbatim."""
        result = _sanitize_csv_export(_df())
        assert result["RESOURCE_TAGS"].iloc[0] == "'=1+1"
        assert "=1+1" not in result.to_csv(index=False).replace("'=1+1", "")

    def test_numbers_are_left_untouched(self):
        """Finite numbers, numeric columns and numeric strings stay as they are."""
        result = _sanitize_csv_export(_df())
        assert result["SEVERITY"].iloc[0] == 4.5
        df = pd.DataFrame({"VALUE": ["-3.5", "+42"]})
        result = _sanitize_csv_export(df)
        assert result["VALUE"].iloc[0] == "-3.5"
        assert result["VALUE"].iloc[1] == "+42"

    def test_plain_text_is_left_untouched(self):
        result = _sanitize_csv_export(_df())
        assert result["PROVIDER"].iloc[0] == "aws"
        assert result["STATUS"].iloc[0] == "FAIL"

    def test_original_dataframe_is_not_mutated(self):
        df = _df()
        _sanitize_csv_export(df)
        assert df["RESOURCE_TAGS"].iloc[0] == "=1+1"

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("=1+1", "'=1+1"),
            ("+1+1", "'+1+1"),
            ("-1+1", "'-1+1"),
            ("@cmd", "'@cmd"),
            ("\tcmd", "'\tcmd"),
            ("\rcmd", "'\rcmd"),
            ('=SUM("a,b")\nnext', '\'=SUM("a,b")\nnext'),
            (" =1+1", "' =1+1"),
            ("\t42", "'\t42"),
            ("-3.5", "-3.5"),
            ("+42", "+42"),
            ("plain-text", "plain-text"),
        ],
    )
    def test_csv_download_contains_only_sanitized_filtered_rows(
        self, monkeypatch, value, expected
    ):
        """Exercise the download callback and inspect the actual CSV payload."""
        data = pd.DataFrame(
            {
                "PROVIDER": ["aws", "aws"],
                "ACCOUNT_UID": ["test-account", "test-account"],
                "REGION": ["us-east-1", "us-west-2"],
                "SERVICE_NAME": ["s3", "s3"],
                "CHECK_ID": ["check-one", "check-two"],
                "CHECK_TITLE": ["First check", "Second check"],
                "RESOURCE_TAGS": [value, "=excluded"],
                "STATUS": ["PASS", "PASS"],
                "SEVERITY": ["high", "high"],
                "ASSESSMENT_TIME": ["2026-10-01", "2026-10-01"],
                "TIMESTAMP": pd.to_datetime(["2026-10-01", "2026-10-01"]),
            }
        )
        original = data.copy(deep=True)
        monkeypatch.setattr(overview, "data", data)
        monkeypatch.setattr(overview, "csv_files", [])
        monkeypatch.setattr(
            overview, "ctx", SimpleNamespace(triggered_id="download_link_csv")
        )
        # Layout generation is unrelated to the download payload being tested.
        monkeypatch.setattr(overview, "create_provider_card", lambda *args: None)
        monkeypatch.setattr(overview, "generate_table", lambda *args: None)

        result = overview.filter_data(
            cloud_account_values=["All"],
            region_account_values=["us-east-1"],
            assessment_value="2026-10-01",
            n_clicks_csv=1,
            n_clicks_xlsx=0,
            severity_values=["All"],
            service_values=["All"],
            provider_values=["All"],
            table_row_values=100,
            status_values=["All"],
            category_values=["All"],
            search_value=None,
            aws_clicks=0,
            azure_clicks=0,
            gcp_clicks=0,
            k8s_clicks=0,
            m365_clicks=0,
            sort_button_check_name=0,
            sort_button_severity=0,
            sort_button_status=0,
            sort_button_region=0,
            sort_button_service=0,
            sort_button_account=0,
            alibabacloud_clicks=0,
        )
        download = result[4]
        assert download["filename"] == "prowler-dashboard-export.csv"
        assert download["base64"] is False
        rows = list(csv.DictReader(StringIO(download["content"])))
        assert len(rows) == 1
        assert rows[0]["RESOURCE_TAGS"] == expected
        assert rows[0]["REGION"] == "us-east-1"
        assert "=excluded" not in download["content"]
        assert not download["content"].startswith(",")
        pd.testing.assert_frame_equal(data, original)

    def test_empty_dataframe_is_preserved(self):
        data = pd.DataFrame(columns=["RESOURCE_TAGS"])
        pd.testing.assert_frame_equal(_sanitize_csv_export(data), data)
