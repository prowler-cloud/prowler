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

    # Ensure missing columns are handled or replaced with placeholder values
    for col in required_columns:
        if col not in data.columns:
            # Fill missing columns with placeholder values
            if col == "REQUIREMENTS_ATTRIBUTES_CATEGORY":
                data[col] = "Unknown Category"
            elif col == "REQUIREMENTS_ATTRIBUTES_OBJECTIVE_ID":
                data[col] = "Unknown Objective ID"
            elif col == "REQUIREMENTS_ATTRIBUTES_OBJECTIVE_NAME":
                data[col] = "Unknown Objective Name"
            else:
                data[col] = "Unknown"

    aux = data.copy()

    return get_section_container_update_iso(
        aux, "REQUIREMENTS_ATTRIBUTES_CATEGORY", "REQUIREMENTS_ATTRIBUTES_OBJECTIVE_ID"
    )
