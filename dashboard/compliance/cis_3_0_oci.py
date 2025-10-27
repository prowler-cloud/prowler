import warnings

from dashboard.common_methods import get_section_containers_cis

warnings.filterwarnings("ignore")


def get_table(data):
    """
    Generate CIS OCI Foundations Benchmark v3.0 compliance table.

    Args:
        data: DataFrame containing compliance check results with columns:
            - REQUIREMENTS_ID: CIS requirement ID (e.g., "1.1", "2.1")
            - REQUIREMENTS_DESCRIPTION: Description of the requirement
            - REQUIREMENTS_ATTRIBUTES_SECTION: CIS section name
            - CHECKID: Prowler check identifier
            - STATUS: Check status (PASS/FAIL)
            - REGION: OCI region
            - TENANCYID: OCI tenancy OCID
            - RESOURCEID: Resource OCID or identifier

    Returns:
        Section containers organized by CIS sections for dashboard display
    """
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "TENANCYID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_cis(
        aux, "REQUIREMENTS_ID", "REQUIREMENTS_ATTRIBUTES_SECTION"
    )
