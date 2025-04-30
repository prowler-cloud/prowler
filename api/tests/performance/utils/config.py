import os

USER_EMAIL = os.environ.get("USER_EMAIL")
USER_PASSWORD = os.environ.get("USER_PASSWORD")

BASE_HEADERS = {"Content-Type": "application/vnd.api+json"}

FINDINGS_UI_SORT_VALUES = ["severity", "status", "-inserted_at"]
TARGET_INSERTED_AT = os.environ.get("TARGET_INSERTED_AT", "2025-04-22")

FINDINGS_RESOURCE_METADATA = {
    "regions": "region",
    "resource_types": "resource_type",
    "services": "service",
}

S_PROVIDER_NAME = "provider-50k"
M_PROVIDER_NAME = "provider-250k"
L_PROVIDER_NAME = "provider-500k"
