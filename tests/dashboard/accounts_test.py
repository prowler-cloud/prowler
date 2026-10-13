import pandas as pd

from dashboard.lib.accounts import (
    build_aws_account_names,
    format_aws_account_label,
    is_valid_account_name,
    load_aws_account_names,
)
from dashboard.lib.dropdowns import to_dropdown_options


def _findings(rows):
    return pd.DataFrame(rows, columns=["PROVIDER", "ACCOUNT_UID", "ACCOUNT_NAME"])


class TestIsValidAccountName:
    def test_valid_name(self):
        assert is_valid_account_name("prod-payments")

    def test_empty_nan_and_non_string_are_invalid(self):
        for name in ["", "   ", "nan", "NaN", None, float("nan"), 123]:
            assert not is_valid_account_name(name)


class TestBuildAwsAccountNames:
    def test_maps_aws_accounts_with_names(self):
        data = _findings(
            [
                ["aws", "111111111111", "prod-payments"],
                ["aws", "222222222222", "nan"],
                ["aws", "333333333333", ""],
                ["azure", "sub-id", "my-subscription"],
            ]
        )
        assert build_aws_account_names(data) == {"111111111111": "prod-payments"}

    def test_missing_columns_returns_empty(self):
        data = pd.DataFrame({"PROVIDER": ["aws"], "ACCOUNT_UID": ["111111111111"]})
        assert build_aws_account_names(data) == {}
        assert build_aws_account_names(None) == {}


class TestLoadAwsAccountNames:
    def test_reads_names_from_findings_csvs(self, tmp_path):
        (tmp_path / "scan.csv").write_text(
            "PROVIDER;ACCOUNT_UID;ACCOUNT_NAME;CHECK_ID\n"
            "aws;012345678901;prod-payments;check_a\n"
            "aws;222222222222;;check_b\n"
        )
        assert load_aws_account_names(str(tmp_path)) == {
            "012345678901": "prod-payments"
        }

    def test_file_without_name_column_is_ignored(self, tmp_path):
        (tmp_path / "scan.csv").write_text(
            "PROVIDER;ACCOUNT_UID;CHECK_ID\naws;111111111111;check_a\n"
        )
        assert load_aws_account_names(str(tmp_path)) == {}


class TestFormatAwsAccountLabel:
    def test_with_name(self):
        assert (
            format_aws_account_label("111111111111", {"111111111111": "prod"})
            == "prod (111111111111)"
        )

    def test_without_name(self):
        assert format_aws_account_label("111111111111", {}) == "111111111111"


class TestToDropdownOptions:
    def test_mixed_strings_and_dicts(self):
        aws_option = {
            "label": "prod (111111111111) - AWS",
            "value": "111111111111 - AWS",
        }
        assert to_dropdown_options(["All", aws_option]) == [
            {"label": "All", "value": "All"},
            aws_option,
        ]
