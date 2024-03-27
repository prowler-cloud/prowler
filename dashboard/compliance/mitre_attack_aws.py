import warnings

from dashboard.common_methods import get_section_containers_format2

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_SUBTECHNIQUES",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_format2(
        aux, "REQUIREMENTS_ID", "REQUIREMENTS_SUBTECHNIQUES"
    )
