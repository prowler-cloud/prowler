import pandas as pd

from dashboard.pages.compliance import _ensure_scope_columns


def _df(columns):
    """Build a one-row DataFrame preserving the given column order."""
    return pd.DataFrame({col: ["x"] for col in columns})


class TestEnsureScopeColumns:
    def test_aws_account_and_region_preserved(self):
        """A provider that already emits ACCOUNTID and REGION is left untouched."""
        df = _df(["PROVIDER", "DESCRIPTION", "ACCOUNTID", "REGION", "ASSESSMENTDATE"])
        result = _ensure_scope_columns(df)
        assert "ACCOUNTID" in result.columns
        assert "REGION" in result.columns
        assert result["ACCOUNTID"].iloc[0] == "x"

    def test_okta_single_scope_column_becomes_accountid(self):
        """Okta's ORGANIZATIONDOMAIN becomes ACCOUNTID; REGION falls back."""
        df = _df(["PROVIDER", "DESCRIPTION", "ORGANIZATIONDOMAIN", "ASSESSMENTDATE"])
        df["ORGANIZATIONDOMAIN"] = ["trial-123.okta.com"]
        result = _ensure_scope_columns(df)
        assert "ACCOUNTID" in result.columns
        assert "ORGANIZATIONDOMAIN" not in result.columns
        assert result["ACCOUNTID"].iloc[0] == "trial-123.okta.com"
        assert result["REGION"].iloc[0] == "-"

    def test_two_unknown_scope_columns_map_to_account_and_region(self):
        """Two scope columns map positionally to ACCOUNTID and REGION."""
        df = _df(["PROVIDER", "DESCRIPTION", "TENANCYID", "LOCATION", "ASSESSMENTDATE"])
        df["TENANCYID"] = ["tenant-1"]
        df["LOCATION"] = ["eu-west-1"]
        result = _ensure_scope_columns(df)
        assert result["ACCOUNTID"].iloc[0] == "tenant-1"
        assert result["REGION"].iloc[0] == "eu-west-1"

    def test_no_scope_columns_fall_back_to_dash(self):
        """No scope columns → both ACCOUNTID and REGION fall back to '-'."""
        df = _df(["PROVIDER", "DESCRIPTION", "ASSESSMENTDATE"])
        result = _ensure_scope_columns(df)
        assert result["ACCOUNTID"].iloc[0] == "-"
        assert result["REGION"].iloc[0] == "-"

    def test_missing_anchors_still_fall_back_to_dash(self):
        """Without DESCRIPTION/ASSESSMENTDATE anchors, both fall back to '-'."""
        df = _df(["PROVIDER", "FOO", "BAR"])
        result = _ensure_scope_columns(df)
        assert result["ACCOUNTID"].iloc[0] == "-"
        assert result["REGION"].iloc[0] == "-"

    def test_existing_accountid_does_not_consume_region_scope(self):
        """An existing ACCOUNTID is kept; the leftover scope becomes REGION."""
        df = _df(["PROVIDER", "DESCRIPTION", "ACCOUNTID", "LOCATION", "ASSESSMENTDATE"])
        df["ACCOUNTID"] = ["acc-1"]
        df["LOCATION"] = ["us-east-2"]
        result = _ensure_scope_columns(df)
        assert result["ACCOUNTID"].iloc[0] == "acc-1"
        assert result["REGION"].iloc[0] == "us-east-2"
