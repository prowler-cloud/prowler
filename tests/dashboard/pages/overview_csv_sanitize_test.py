import pandas as pd

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
