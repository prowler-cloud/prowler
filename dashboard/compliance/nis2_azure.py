import warnings

from dashboard.common_methods import get_section_containers_3_levels

warnings.filterwarnings("ignore")


def get_table(data):
    data["REQUIREMENTS_DESCRIPTION"] = (
        data["REQUIREMENTS_ID"] + " - " + data["REQUIREMENTS_DESCRIPTION"]
    )

    data["REQUIREMENTS_DESCRIPTION"] = data["REQUIREMENTS_DESCRIPTION"].apply(
        lambda x: x[:150] + "..." if len(str(x)) > 150 else x
    )

    data["REQUIREMENTS_ATTRIBUTES_SECTION"] = data[
        "REQUIREMENTS_ATTRIBUTES_SECTION"
    ].apply(lambda x: x[:80] + "..." if len(str(x)) > 80 else x)

    data["REQUIREMENTS_ATTRIBUTES_SUBSECTION"] = data[
        "REQUIREMENTS_ATTRIBUTES_SUBSECTION"
    ].apply(lambda x: x[:150] + "..." if len(str(x)) > 150 else x)

    aux = data[
        [
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]

    return get_section_containers_3_levels(
        aux,
        "REQUIREMENTS_ATTRIBUTES_SECTION",
        "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
        "REQUIREMENTS_DESCRIPTION",
    )
