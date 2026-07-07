import warnings

from dashboard.common_methods import get_section_containers_format2

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

    # Sort alphabetically since KSI IDs (ksi-cmt-lmc) are not numeric versions
    aux.sort_values(by="REQUIREMENTS_ID", inplace=True)

    return get_section_containers_format2(
        aux, "REQUIREMENTS_ATTRIBUTES_SECTION", "REQUIREMENTS_ID"
    )
