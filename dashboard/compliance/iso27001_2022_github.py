import warnings

from dashboard.common_methods import get_section_container_iso

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ATTRIBUTES_CATEGORY",
            "REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID",
            "REQUIREMENTS_ATTRIBUTES_OBJETIVE_NAME",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]
    return get_section_container_iso(
        aux, "REQUIREMENTS_ATTRIBUTES_CATEGORY", "REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID"
    )
