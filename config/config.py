from datetime import datetime

timestamp = datetime.today()
prowler_version = "3.0-alfa"

# Groups
groups_file = "groups.json"

# AWS services-regions matrix json
aws_services_json_url = (
    "https://api.regional-table.region-services.aws.a2z.com/index.json"
)
aws_services_json_file = "providers/aws/aws_regions_services.json"


csv_header = [
    "PROVIDER",
    "PROFILE",
    "ACCOUNT_ID",
    "REGION",
    "CHECKID",
    "CHECKNAME",
    "CHECKTITLE",
    "STATUS",
    "RESULT_EXTENDED",
    "CHECKTYPE",
    "SERVICENAME",
    "SUBSERVICENAME",
    "RESOURCEIDTEMPLATE",
    "SEVERITY",
    "RESPOURCETYPE",
    "DESCRIPTION",
    "RISK",
    "RELATED_URL",
    "REMEDIATION_RECOMMENDATION_TEXT",
    "REMEDIATION_RECOMMENDATION_URL",
    "REMEDIATION_RECOMMENDATION_CODE_NATIVEIAC",
    "REMEDIATION_RECOMMENDATION_CODE_TERRAFORM",
    "REMEDIATION_RECOMMENDATION_CODE_CLI",
    "REMEDIATION_RECOMMENDATION_CODE_OTHER",
    "CATEGORIES",
    "TAGS",
    "DEPENDS_ON",
    "RELATED_TO",
    "NOTES",
    "COMPLIANCE",
    "ASSESSMENT_TIME",
    # "ACCOUNT_DETAILS_EMAIL",
    # "ACCOUNT_DETAILS_NAME",
    # "ACCOUNT_DETAILS_ARN",
    # "ACCOUNT_DETAILS_ORG",
    # "ACCOUNT_DETAILS_TAGS",
    "ORGANIZATIONS_INFO",
]
