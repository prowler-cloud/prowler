import warnings

from dashboard.common_methods import get_section_containers_threatscore

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_threatscore(
        aux,
        "REQUIREMENTS_ATTRIBUTES_SECTION",
        "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
        "REQUIREMENTS_ID",
    )
