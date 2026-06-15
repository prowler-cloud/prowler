import pandas as pd
from dash import dash_table

from dashboard.common_methods import get_section_containers_generic


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


def _df(**extra):
    data = {
        "REQUIREMENTS_ID": ["req1"],
        "STATUS": ["PASS"],
        "CHECKID": ["check1"],
        "REGION": ["us-east-1"],
        "ACCOUNTID": ["123"],
        "RESOURCEID": ["res1"],
    }
    data.update(extra)
    return pd.DataFrame(data)


class TestGetSectionContainersGeneric:
    def test_one_container_per_section(self):
        """One outer container per distinct section value."""
        df = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Sec A", "Sec A", "Sec B"],
                "REQUIREMENTS_ID": ["req1", "req2", "req3"],
                "STATUS": ["PASS", "FAIL", "PASS"],
                "CHECKID": ["c1", "c2", "c3"],
                "REGION": ["-"] * 3,
                "ACCOUNTID": ["123"] * 3,
                "RESOURCEID": ["r1", "r2", "r3"],
            }
        )
        result = get_section_containers_generic(
            df, "REQUIREMENTS_ATTRIBUTES_SECTION", "REQUIREMENTS_ID"
        )
        assert len(result.children) == 2

    def test_inner_title_includes_id_and_description(self):
        """Inner accordion title is '<id> - <description>'."""
        df = _df(
            REQUIREMENTS_ATTRIBUTES_SECTION=["Sec A"],
            REQUIREMENTS_DESCRIPTION=["Ensure MFA"],
        )
        rendered = str(
            get_section_containers_generic(
                df, "REQUIREMENTS_ATTRIBUTES_SECTION", "REQUIREMENTS_ID"
            )
        )
        assert "req1 - Ensure MFA" in rendered

    def test_arbitrary_ids_do_not_crash(self):
        """Non-numeric ids are sorted lexicographically without raising."""
        df = pd.DataFrame(
            {
                "REQUIREMENTS_ATTRIBUTES_SECTION": ["Sec A"] * 3,
                "REQUIREMENTS_ID": ["AC-2(1)", "foo-bar", "step.1.2"],
                "STATUS": ["PASS", "FAIL", "PASS"],
                "CHECKID": ["c1", "c2", "c3"],
                "REGION": ["-"] * 3,
                "ACCOUNTID": ["123"] * 3,
                "RESOURCEID": ["r1", "r2", "r3"],
            }
        )
        result = get_section_containers_generic(
            df, "REQUIREMENTS_ATTRIBUTES_SECTION", "REQUIREMENTS_ID"
        )
        tables = _datatable_column_ids(result)
        assert tables and all("CHECKID" in cols for cols in tables)
