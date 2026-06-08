import warnings

from dashboard.common_methods import get_section_containers_format4

warnings.filterwarnings("ignore")


def get_table(data):
    # Discover REQUIREMENTS_ATTRIBUTES_* columns at runtime.
    attr_cols = [c for c in data.columns if c.startswith("REQUIREMENTS_ATTRIBUTES_")]

    # Grouping column selection (in priority order):
    #   1. REQUIREMENTS_ATTRIBUTES_SECTION if present — most common convention
    #   2. First discovered attribute column — covers novel attribute schemas
    #   3. REQUIREMENTS_ID as flat/section-less fallback
    if "REQUIREMENTS_ATTRIBUTES_SECTION" in attr_cols:
        grouping_col = "REQUIREMENTS_ATTRIBUTES_SECTION"
    elif attr_cols:
        grouping_col = attr_cols[0]
    else:
        grouping_col = "REQUIREMENTS_ID"

    # Build the column subset that get_section_containers_format4 needs.
    # grouping_col is prepended only when it differs from REQUIREMENTS_ID to
    # avoid a duplicate column entry in the subset list.
    needed = []
    if grouping_col != "REQUIREMENTS_ID":
        needed.append(grouping_col)
    needed.extend(
        ["REQUIREMENTS_ID", "STATUS", "CHECKID", "REGION", "ACCOUNTID", "RESOURCEID"]
    )
    for optional_col in ("REQUIREMENTS_NAME", "REQUIREMENTS_DESCRIPTION"):
        if optional_col in data.columns:
            needed.append(optional_col)

    present = [c for c in needed if c in data.columns]
    aux = data[present].copy()

    return get_section_containers_format4(aux, grouping_col)
