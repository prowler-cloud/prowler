import pandas as pd
from dash import dash_table, html

from dashboard.compliance.generic import get_table


def _make_minimal_df(**extra_cols):
    """Create a minimal valid DataFrame for get_table tests."""
    data = {
        "REQUIREMENTS_ID": ["req1"],
        "STATUS": ["PASS"],
        "CHECKID": ["check1"],
        "REGION": ["us-east-1"],
        "ACCOUNTID": ["123456789"],
        "RESOURCEID": ["res1"],
    }
    data.update(extra_cols)
    return pd.DataFrame(data)


def _datatable_column_ids(component):
    """Collect the column ids of every DataTable in a Dash component tree."""
    if isinstance(component, dash_table.DataTable):
        return [[c["id"] for c in component.columns]]
    children = getattr(component, "children", None)
    if children is None:
        return []
    if not isinstance(children, (list, tuple)):
        children = [children]
    return [cols for child in children for cols in _datatable_column_ids(child)]


class TestGetTable:
    def test_groups_by_section(self):
        """SC-001a: df with REQUIREMENTS_ATTRIBUTES_SECTION returns Div grouped by section."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": [
                    "Section A",
                    "Section A",
                    "Section A",
                    "Section B",
                    "Section B",
                ],
                "REQUIREMENTS_ID": [
                    "ctrl-alpha",
                    "ctrl-alpha",
                    "ctrl-alpha",
                    "ctrl-beta",
                    "ctrl-beta",
                ],
                "STATUS": ["PASS", "FAIL", "PASS", "FAIL", "FAIL"],
                "CHECKID": ["check1", "check2", "check3", "check4", "check5"],
                "REGION": ["us-east-1"] * 5,
                "ACCOUNTID": ["123"] * 5,
                "RESOURCEID": ["res1", "res2", "res3", "res4", "res5"],
            }
        )
        result = get_table(data)
        assert isinstance(result, html.Div)
        assert result.className == "compliance-data-layout"
        assert len(result.children) == 2  # one container per distinct section

    def test_flat_fallback_no_attributes(self):
        """SC-001b: No REQUIREMENTS_ATTRIBUTES_* cols → grouped by REQUIREMENTS_ID."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["req1", "req1", "req2"],
                "STATUS": ["PASS", "FAIL", "FAIL"],
                "CHECKID": ["check1", "check2", "check3"],
                "REGION": ["us-east-1"] * 3,
                "ACCOUNTID": ["123"] * 3,
                "RESOURCEID": ["res1", "res2", "res3"],
            }
        )
        result = get_table(data)
        assert isinstance(result, html.Div)
        assert result.className == "compliance-data-layout"
        # 2 distinct REQUIREMENTS_ID values → 2 group containers
        assert len(result.children) == 2

    def test_arbitrary_ids_no_crash(self):
        """ADR-2 / R1 regression guard: non-numeric REQUIREMENTS_IDs must not raise ValueError.

        get_section_containers_cis sorts by version_tuple which calls int() on each
        dotted/dashed segment and crashes on IDs like 'AC-2(1)'. Selecting format4
        (no version sort) is the fix. This test is a permanent guard against regression.
        """
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ID": ["AC-2(1)", "foo-bar", "step.1.2"],
                "STATUS": ["PASS", "FAIL", "PASS"],
                "CHECKID": ["check1", "check2", "check3"],
                "REGION": ["us-east-1"] * 3,
                "ACCOUNTID": ["123"] * 3,
                "RESOURCEID": ["res1", "res2", "res3"],
            }
        )
        # Must not raise ValueError
        result = get_table(data)
        assert isinstance(result, html.Div)

    def test_discovers_multiple_attribute_columns(self):
        """SC-005a: Multiple REQUIREMENTS_ATTRIBUTES_* cols present → no AttributeError;
        component tree is non-empty."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Sec A", "Sec B"],
                "REQUIREMENTS_ATTRIBUTES_CATEGORY": ["Cat 1", "Cat 2"],
                "REQUIREMENTS_ATTRIBUTES_CONTROL_ID": ["C1", "C2"],
                "REQUIREMENTS_ID": ["req1", "req2"],
                "STATUS": ["PASS", "FAIL"],
                "CHECKID": ["check1", "check2"],
                "REGION": ["us-east-1"] * 2,
                "ACCOUNTID": ["123"] * 2,
                "RESOURCEID": ["res1", "res2"],
            }
        )
        result = get_table(data)
        assert isinstance(result, html.Div)
        assert result.children  # non-empty component tree

    def test_novel_attribute_column_names(self):
        """SC-005b: Novel attr col names without a SECTION col → first attr col used as
        grouping; returns a valid html.Div without any code change required."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_DOMAIN": ["Domain A", "Domain B"],
                "REQUIREMENTS_ATTRIBUTES_SUBDOMAIN": ["Sub 1", "Sub 2"],
                "REQUIREMENTS_ID": ["req1", "req2"],
                "STATUS": ["PASS", "FAIL"],
                "CHECKID": ["check1", "check2"],
                "REGION": ["us-east-1"] * 2,
                "ACCOUNTID": ["123"] * 2,
                "RESOURCEID": ["res1", "res2"],
            }
        )
        result = get_table(data)
        assert isinstance(result, html.Div)
        assert len(result.children) > 0

    def test_manual_only_requirements(self):
        """SC-008a: All rows have STATUS='MANUAL' → returns html.Div with non-empty
        children; result is not the 'No data found' string."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Sec A", "Sec B"],
                "REQUIREMENTS_ID": ["req1", "req2"],
                "STATUS": ["MANUAL", "MANUAL"],
                "CHECKID": ["check1", "check2"],
                "REGION": ["us-east-1"] * 2,
                "ACCOUNTID": ["123"] * 2,
                "RESOURCEID": ["res1", "res2"],
            }
        )
        result = get_table(data)
        assert isinstance(result, html.Div)
        assert not isinstance(result, str)
        assert result.children  # non-empty

    def test_empty_dataframe(self):
        """SC-009a: Zero rows with correct column schema → valid html.Div; no exception."""
        data = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": pd.Series([], dtype=str),
                "REQUIREMENTS_ID": pd.Series([], dtype=str),
                "STATUS": pd.Series([], dtype=str),
                "CHECKID": pd.Series([], dtype=str),
                "REGION": pd.Series([], dtype=str),
                "ACCOUNTID": pd.Series([], dtype=str),
                "RESOURCEID": pd.Series([], dtype=str),
            }
        )
        result = get_table(data)
        assert isinstance(result, html.Div)

    def test_get_table_returns_html_div(self):
        """SC-012a: Smoke test — isinstance(get_table(df), html.Div) is True."""
        data = _make_minimal_df(
            REQUIREMENTS_ATTRIBUTES_SECTION=["Sec A"],
        )
        result = get_table(data)
        assert isinstance(result, html.Div)


class TestNestedRendering:
    def test_section_and_requirement_id_are_separate_levels(self):
        """Section is the outer level; requirement id + description the inner."""
        data = _make_minimal_df(
            REQUIREMENTS_ATTRIBUTES_SECTION=["3 Compute Services"],
            REQUIREMENTS_DESCRIPTION=["Ensure only MFA enabled identities"],
        )
        rendered = str(get_table(data))
        assert "3 Compute Services" in rendered
        assert "req1 - Ensure only MFA enabled identities" in rendered

    def test_checks_table_is_nested_under_requirement(self):
        """The checks table sits at the innermost level."""
        data = _make_minimal_df(
            REQUIREMENTS_ATTRIBUTES_SECTION=["Sec A"],
            REQUIREMENTS_DESCRIPTION=["Some requirement"],
        )
        tables = _datatable_column_ids(get_table(data))
        assert tables and all("CHECKID" in cols for cols in tables)
