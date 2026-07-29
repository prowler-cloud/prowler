from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from dash import html

from dashboard.pages.compliance import _dispatch_compliance_renderer


def _make_dispatch_df(**extra_cols):
    """Minimal DataFrame with the columns required by the dedup step."""
    data = {
        "REQUIREMENTS_ID": ["req1", "req2"],
        "REQUIREMENTS_ATTRIBUTES_SECTION": ["Sec A", "Sec A"],
        "STATUS": ["PASS", "FAIL"],
        "CHECKID": ["check1", "check2"],
        "RESOURCEID": ["res1", "res2"],
        "STATUSEXTENDED": ["", ""],
        "REGION": ["us-east-1", "us-east-1"],
        "ACCOUNTID": ["123456789", "123456789"],
    }
    data.update(extra_cols)
    return pd.DataFrame(data)


class TestDispatchComplianceRenderer:
    def test_builtin_name_uses_builtin_module(self):
        """SC-002a: analytics_input='cis_4_0_aws' resolves real builtin module;
        returns (html.Div, DataFrame) 2-tuple."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["1.1", "1.2"],
                "REQUIREMENTS_DESCRIPTION": ["Description 1", "Description 2"],
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Section A", "Section A"],
                "CHECKID": ["check1", "check2"],
                "STATUS": ["PASS", "FAIL"],
                "REGION": ["us-east-1", "us-east-1"],
                "ACCOUNTID": ["123456789", "123456789"],
                "RESOURCEID": ["res1", "res2"],
                "STATUSEXTENDED": ["Pass", "Fail"],
            }
        )
        table, result_data = _dispatch_compliance_renderer(data, "cis_4_0_aws")
        assert isinstance(table, html.Div)
        assert isinstance(result_data, pd.DataFrame)

    def test_unknown_name_falls_back_to_generic(self):
        """SC-003a: Unknown analytics_input raises ModuleNotFoundError → generic
        fallback is called with the deduped dataframe."""
        data = _make_dispatch_df()
        sentinel = MagicMock(
            return_value=html.Div([], className="compliance-data-layout")
        )

        with patch("dashboard.compliance.generic.get_table", sentinel):
            table, result_data = _dispatch_compliance_renderer(data, "myfw_dynprovider")

        sentinel.assert_called_once()
        assert isinstance(table, html.Div)
        assert isinstance(result_data, pd.DataFrame)

    def test_import_error_is_not_swallowed(self):
        """SC-003b: ImportError (NOT ModuleNotFoundError) is re-raised; except clause
        is exact — only ModuleNotFoundError routes to generic."""
        data = _make_dispatch_df()

        with patch(
            "dashboard.pages.compliance.importlib.import_module",
            side_effect=ImportError("custom error"),
        ):
            with pytest.raises(ImportError, match="custom error"):
                _dispatch_compliance_renderer(data, "anything")

    def test_get_table_error_in_generic_surfaces(self):
        """SC-004a: ValueError from generic.get_table propagates (not swallowed);
        get_table is called OUTSIDE the try block."""
        data = _make_dispatch_df()

        with patch(
            "dashboard.compliance.generic.get_table",
            side_effect=ValueError("boom"),
        ):
            with pytest.raises(ValueError, match="boom"):
                _dispatch_compliance_renderer(data, "myfw_dynprovider")

    def test_get_table_error_in_builtin_surfaces(self):
        """REQ-004 / ADR-1: RuntimeError from a builtin get_table propagates;
        proving get_table is called outside the try block."""
        data = _make_dispatch_df()
        mock_module = MagicMock()
        mock_module.get_table.side_effect = RuntimeError("table error")

        with patch(
            "dashboard.pages.compliance.importlib.import_module",
            return_value=mock_module,
        ):
            with pytest.raises(RuntimeError, match="table error"):
                _dispatch_compliance_renderer(data, "some_builtin_fw")

    def test_dedup_applied_before_get_table(self):
        """ADR-1: Duplicate rows (identical CHECKID/STATUS/RESOURCEID/STATUSEXTENDED)
        are dropped; returned data has the deduplicated row count."""
        # Row 0 and row 1 are identical in all dedup-key columns; row 2 is unique.
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Sec A", "Sec A", "Sec B"],
                "REQUIREMENTS_ID": ["req1", "req1", "req2"],
                "STATUS": ["PASS", "PASS", "FAIL"],
                "CHECKID": ["check1", "check1", "check2"],
                "RESOURCEID": ["res1", "res1", "res2"],
                "STATUSEXTENDED": ["", "", ""],
                "REGION": ["us-east-1"] * 3,
                "ACCOUNTID": ["123"] * 3,
            }
        )
        mock_module = MagicMock()
        mock_module.get_table.return_value = html.Div([])

        with patch(
            "dashboard.pages.compliance.importlib.import_module",
            return_value=mock_module,
        ):
            table, result_data = _dispatch_compliance_renderer(data, "some_fw")

        assert len(result_data) == 2  # one duplicate removed

    def test_muted_column_added_to_dedup_when_present(self):
        """ADR-1 edge case: When MUTED column is present, it is included in the dedup
        subset at index 2; rows differing only in MUTED are kept as distinct rows."""
        # Both rows share CHECKID/STATUS/RESOURCEID/STATUSEXTENDED but differ in MUTED.
        # With MUTED in dedup_columns, both rows are kept (2 rows after dedup).
        # Without MUTED in dedup_columns, they would be collapsed to 1 row.
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Sec A", "Sec A"],
                "REQUIREMENTS_ID": ["req1", "req1"],
                "STATUS": ["PASS", "PASS"],
                "CHECKID": ["check1", "check1"],
                "RESOURCEID": ["res1", "res1"],
                "STATUSEXTENDED": ["", ""],
                "MUTED": ["True", "False"],
                "REGION": ["us-east-1", "us-east-1"],
                "ACCOUNTID": ["123", "123"],
            }
        )
        mock_module = MagicMock()
        mock_module.get_table.return_value = html.Div([])

        with patch(
            "dashboard.pages.compliance.importlib.import_module",
            return_value=mock_module,
        ):
            table, result_data = _dispatch_compliance_renderer(data, "some_fw")

        # MUTED at idx 2 means these two rows have different dedup keys → both kept
        assert len(result_data) == 2

    def test_returns_table_and_data_tuple(self):
        """ADR-1 interface contract: _dispatch_compliance_renderer returns a
        2-tuple (table, deduped_data)."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["1.1", "1.2"],
                "REQUIREMENTS_DESCRIPTION": ["Desc 1", "Desc 2"],
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Section A", "Section A"],
                "CHECKID": ["check1", "check2"],
                "STATUS": ["PASS", "FAIL"],
                "REGION": ["us-east-1", "us-east-1"],
                "ACCOUNTID": ["123456789", "123456789"],
                "RESOURCEID": ["res1", "res2"],
                "STATUSEXTENDED": ["", ""],
            }
        )
        result = _dispatch_compliance_renderer(data, "cis_4_0_aws")
        assert isinstance(result, tuple)
        assert len(result) == 2
        table, deduped_data = result
        assert isinstance(table, html.Div)
        assert isinstance(deduped_data, pd.DataFrame)
