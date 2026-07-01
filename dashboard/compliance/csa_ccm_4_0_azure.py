import warnings

from dashboard.common_methods import get_section_containers_kisa_ismsp

warnings.filterwarnings("ignore")


def get_table(data):
    data["REQUIREMENTS_ID"] = (
        data["REQUIREMENTS_ID"] + " - " + data["REQUIREMENTS_DESCRIPTION"]
    )

    data["REQUIREMENTS_ID"] = data["REQUIREMENTS_ID"].apply(
        lambda x: x[:150] + "..." if len(str(x)) > 150 else x
    )

    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_kisa_ismsp(
        aux, "REQUIREMENTS_ATTRIBUTES_SECTION", "REQUIREMENTS_ID"
    )
