"""Huawei Cloud Provider Configuration Constants"""

HUAWEICLOUD_DEFAULT_REGION = "cn-north-4"
ROLE_SESSION_NAME = "ProwlerAssessmentSession"

# Huawei Cloud SDK Configuration
HUAWEICLOUD_SDK_READ_TIMEOUT = 60  # seconds
HUAWEICLOUD_SDK_CONNECT_TIMEOUT = 10  # seconds

# Huawei Cloud Regions - Based on Huawei Cloud documentation
# Source: https://developer.huaweicloud.com/intl/en-us/endpoint
HUAWEICLOUD_REGIONS = {
    # China Regions
    "cn-north-1": "China (Beijing-1)",
    "cn-north-4": "China (Beijing-4)",
    "cn-east-2": "China (Shanghai-2)",
    "cn-east-3": "China (Shanghai-1)",
    "cn-south-1": "China (Guangzhou)",
    "cn-south-2": "China (Guangzhou-2)",
    "cn-south-4": "China (Guangzhou-4)",
    "cn-southwest-2": "China (Guiyang)",
    "cn-north-9": "China (Ulanqab)",
    "cn-north-2": "China (Beijing-2)",
    "cn-east-5": "China (Shanghai-5)",
    "cn-south-5": "China (Guangzhou-5)",
    # Asia-Pacific Regions
    "ap-southeast-1": "Hong Kong",
    "ap-southeast-2": "Singapore",
    "ap-southeast-3": "Thailand",
    "ap-southeast-4": "Malaysia",
    "ap-southeast-5": "Indonesia",
    "ap-south-1": "India",
    # Africa Regions
    "af-south-1": "South Africa",
    # South America Regions
    "sa-brazil-1": "Brazil",
    "la-north-2": "Mexico",
    "la-south-2": "Chile (Santiago)",
    # Europe Regions
    "eu-west-0": "Ireland",
    "eu-west-101": "Ireland (Dublin)",
    "eu-central-2": "Germany (Berlin)",
    # Middle East Regions
    "me-east-1": "UAE (Dubai)",
    # Russia Regions
    "ru-northwest-2": "Russia (Moscow)",
    "ru-moscow-1": "Russia (Moscow-1)",
}

# Global services that don't require region specification
HUAWEICLOUD_GLOBAL_SERVICES = [
    "iam",  # Identity and Access Management
    "bss",  # Billing and Subscription Service
    "organizations",  # Organizations
]

# Service endpoints mapping for services that don't follow standard pattern
# Format: service_name: endpoint_template
HUAWEICLOUD_SERVICE_ENDPOINTS = {
    # Standard pattern is {service}.{region}.myhuaweicloud.com
    # Some services may have different patterns
    "iam": "iam.myhuaweicloud.com",  # IAM is global
    "bss": "bss.myhuaweicloud.com",  # BSS is global
    "organizations": "organizations.myhuaweicloud.com",  # Organizations is global
}

# Huawei Cloud service names mapping to SDK package names
HUAWEICLOUD_SERVICE_SDK_MAPPING = {
    "obs": "huaweicloudsdkobs",
    "ecs": "huaweicloudsdkecs",
    "vpc": "huaweicloudsdkvpc",
    "iam": "huaweicloudsdkiam",
    "rds": "huaweicloudsdkrds",
    "cts": "huaweicloudsdkcts",
    "kms": "huaweicloudsdkkms",
    "waf": "huaweicloudsdkwaf",
    "elb": "huaweicloudsdkelb",
    "evs": "huaweicloudsdkevs",
    "eip": "huaweicloudsdkeip",
    "ims": "huaweicloudsdkims",
    "dns": "huaweicloudsdkdns",
    "antiddos": "huaweicloudsdkantiddos",
    "cbr": "huaweicloudsdkcbr",
    "cce": "huaweicloudsdkcce",
    "ces": "huaweicloudsdkces",
    "css": "huaweicloudsdkcss",
    "dcs": "huaweicloudsdkdcs",
    "ddm": "huaweicloudsdkddm",
    "dds": "huaweicloudsdkdds",
    "dgc": "huaweicloudsdkdgc",
    "dli": "huaweicloudsdkdli",
    "dms": "huaweicloudsdkdms",
    "drs": "huaweicloudsdkdrs",
    "dws": "huaweicloudsdkdws",
    "functiongraph": "huaweicloudsdkfunctiongraph",
    "ges": "huaweicloudsdkges",
    "hss": "huaweicloudsdkhss",
    "live": "huaweicloudsdklive",
    "lts": "huaweicloudsdklts",
    "mrs": "huaweicloudsdkmrs",
    "nat": "huaweicloudsdknat",
    "rms": "huaweicloudsdkrms",
    "rocketmq": "huaweicloudsdkrocketmq",
    "servicestage": "huaweicloudsdkservicestage",
    "smn": "huaweicloudsdksmn",
    "sms": "huaweicloudsdksms",
    "vpn": "huaweicloudsdkvpn",
}
