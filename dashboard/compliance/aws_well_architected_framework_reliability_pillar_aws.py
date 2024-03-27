import warnings

from dashboard.common_methods import get_section_containers_format2

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ATTRIBUTES_NAME",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]
    return get_section_containers_format2(
        aux, "REQUIREMENTS_ATTRIBUTES_NAME", "REQUIREMENTS_ATTRIBUTES_SECTION"
    )
