import warnings

from dashboard.common_methods import get_section_containers_pci

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]

    return get_section_containers_pci(aux, "REQUIREMENTS_ID")
