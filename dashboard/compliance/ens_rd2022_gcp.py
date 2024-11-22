import warnings

from dashboard.common_methods import get_section_containers_ens

warnings.filterwarnings("ignore")


def get_table(data):
    # append the requirements_description to idgrupocontrol
    data["REQUIREMENTS_ATTRIBUTES_IDGRUPOCONTROL"] = (
        data["REQUIREMENTS_ATTRIBUTES_IDGRUPOCONTROL"]
        + " - "
        + data["REQUIREMENTS_DESCRIPTION"]
    )

    aux = data[
        [
            "REQUIREMENTS_ATTRIBUTES_MARCO",
            "REQUIREMENTS_ATTRIBUTES_CATEGORIA",
            "REQUIREMENTS_ATTRIBUTES_IDGRUPOCONTROL",
            "REQUIREMENTS_ATTRIBUTES_TIPO",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]

    return get_section_containers_ens(
        aux,
        "REQUIREMENTS_ATTRIBUTES_MARCO",
        "REQUIREMENTS_ATTRIBUTES_CATEGORIA",
        "REQUIREMENTS_ATTRIBUTES_IDGRUPOCONTROL",
        "REQUIREMENTS_ATTRIBUTES_TIPO",
    )
