import warnings

from dashboard.common_methods import get_section_containers_cis

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_cis(
        aux, "REQUIREMENTS_ID", "REQUIREMENTS_ATTRIBUTES_SECTION"
    )
