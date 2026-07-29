import warnings

from dashboard.common_methods import (
    get_section_containers_format4,
    get_section_containers_generic,
)

warnings.filterwarnings("ignore")


def get_table(data):
    # Discover REQUIREMENTS_ATTRIBUTES_* columns at runtime.
    attr_cols = [c for c in data.columns if c.startswith("REQUIREMENTS_ATTRIBUTES_")]

    # Section column (in priority order):
    #   1. REQUIREMENTS_ATTRIBUTES_SECTION — most common convention
    #   2. First discovered attribute column — covers novel schemas
    #   3. None — no section, group flat by requirement id
    if "REQUIREMENTS_ATTRIBUTES_SECTION" in attr_cols:
        section_col = "REQUIREMENTS_ATTRIBUTES_SECTION"
    elif attr_cols:
        section_col = attr_cols[0]
    else:
        section_col = None

    base_cols = [
        "REQUIREMENTS_ID",
        "REQUIREMENTS_DESCRIPTION",
        "STATUS",
        "CHECKID",
        "REGION",
        "ACCOUNTID",
        "RESOURCEID",
    ]

    # Two levels (section -> requirement id) when a section distinct from the
    # id exists; otherwise group flat by requirement id.
    if section_col and section_col != "REQUIREMENTS_ID":
        needed = [section_col] + base_cols
        aux = data[[c for c in needed if c in data.columns]].copy()
        return get_section_containers_generic(aux, section_col, "REQUIREMENTS_ID")

    aux = data[[c for c in base_cols if c in data.columns]].copy()
    return get_section_containers_format4(aux, "REQUIREMENTS_ID")
