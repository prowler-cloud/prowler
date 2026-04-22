import warnings

from dashboard.common_methods import get_section_containers_rbi

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]
    return get_section_containers_rbi(aux, "REQUIREMENTS_ID")
