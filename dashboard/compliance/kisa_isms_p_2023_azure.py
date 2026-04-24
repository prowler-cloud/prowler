import warnings

from dashboard.common_methods import get_section_containers_3_levels

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ATTRIBUTES_DOMAIN",
            "REQUIREMENTS_ATTRIBUTES_SUBDOMAIN",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "LOCATION",
            "SUBSCRIPTIONID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_3_levels(
        aux,
        "REQUIREMENTS_ATTRIBUTES_DOMAIN",
        "REQUIREMENTS_ATTRIBUTES_SUBDOMAIN",
        "REQUIREMENTS_ATTRIBUTES_SECTION",
    )
