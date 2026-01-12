import warnings

from dashboard.common_methods import get_section_containers_format3

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "REQUIREMENTS_DESCRIPTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_format3(
        aux, "REQUIREMENTS_ATTRIBUTES_SECTION", "REQUIREMENTS_ID"
    )
