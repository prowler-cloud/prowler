from dashboard.common_methods import get_section_container_update_iso

def get_table(data):
    required_columns = [
        "REQUIREMENTS_ATTRIBUTES_CATEGORY",
        "REQUIREMENTS_ATTRIBUTES_OBJECTIVE_ID",
        "REQUIREMENTS_ATTRIBUTES_OBJECTIVE_NAME",
        "CHECKID",
        "STATUS",
        "REGION",
        "ACCOUNTID",
        "RESOURCEID",
    ]

    # Ensure missing columns are handled or replaced
    aux = data.copy()

    return get_section_container_update_iso(
        aux, "REQUIREMENTS_ATTRIBUTES_CATEGORY", "REQUIREMENTS_ATTRIBUTES_OBJECTIVE_ID"
    )
