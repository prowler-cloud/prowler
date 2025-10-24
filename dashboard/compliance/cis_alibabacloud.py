"""
CIS Alibaba Cloud Compliance Dashboard

This module generates compliance reports for the CIS Alibaba Cloud Foundations Benchmark.
"""

import warnings

from dashboard.common_methods import get_section_containers_3_levels

warnings.filterwarnings("ignore")


def get_table(data):
    """
    Generate compliance table for CIS Alibaba Cloud framework

    This function processes compliance data and formats it for dashboard display,
    with sections, subsections, and individual requirements.

    Args:
        data: DataFrame containing compliance data with columns:
            - REQUIREMENTS_ID: Requirement identifier (e.g., "2.1", "4.1")
            - REQUIREMENTS_DESCRIPTION: Description of the requirement
            - REQUIREMENTS_ATTRIBUTES_SECTION: Main section (e.g., "2. Storage")
            - REQUIREMENTS_ATTRIBUTES_SUBSECTION: Subsection (e.g., "2.1 ECS Disk Encryption")
            - CHECKID: Associated Prowler check ID
            - STATUS: Check status (PASS/FAIL)
            - REGION: Alibaba Cloud region
            - ACCOUNTID: Alibaba Cloud account ID
            - RESOURCEID: Resource identifier

    Returns:
        Dashboard table with hierarchical compliance structure
    """
    # Format requirement descriptions with ID prefix and truncate if too long
    data["REQUIREMENTS_DESCRIPTION"] = (
        data["REQUIREMENTS_ID"] + " - " + data["REQUIREMENTS_DESCRIPTION"]
    )

    data["REQUIREMENTS_DESCRIPTION"] = data["REQUIREMENTS_DESCRIPTION"].apply(
        lambda x: x[:150] + "..." if len(str(x)) > 150 else x
    )

    # Truncate section names if too long
    data["REQUIREMENTS_ATTRIBUTES_SECTION"] = data[
        "REQUIREMENTS_ATTRIBUTES_SECTION"
    ].apply(lambda x: x[:80] + "..." if len(str(x)) > 80 else x)

    # Truncate subsection names if too long
    data["REQUIREMENTS_ATTRIBUTES_SUBSECTION"] = data[
        "REQUIREMENTS_ATTRIBUTES_SUBSECTION"
    ].apply(lambda x: x[:150] + "..." if len(str(x)) > 150 else x)

    # Select relevant columns for display
    display_data = data[
        [
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]

    # Generate hierarchical table with 3 levels (Section > Subsection > Requirement)
    return get_section_containers_3_levels(
        display_data,
        "REQUIREMENTS_ATTRIBUTES_SECTION",
        "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
        "REQUIREMENTS_DESCRIPTION",
    )
