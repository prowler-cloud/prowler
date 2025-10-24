"""
Alibaba Cloud Provider Configuration

This module contains configuration constants for the Alibaba Cloud provider.
"""

# Default Alibaba Cloud regions
ALIBABACLOUD_REGIONS = [
    "cn-hangzhou",      # China (Hangzhou)
    "cn-shanghai",      # China (Shanghai)
    "cn-qingdao",       # China (Qingdao)
    "cn-beijing",       # China (Beijing)
    "cn-zhangjiakou",   # China (Zhangjiakou)
    "cn-huhehaote",     # China (Hohhot)
    "cn-wulanchabu",    # China (Ulanqab)
    "cn-shenzhen",      # China (Shenzhen)
    "cn-heyuan",        # China (Heyuan)
    "cn-guangzhou",     # China (Guangzhou)
    "cn-chengdu",       # China (Chengdu)
    "cn-hongkong",      # China (Hong Kong)
    "ap-northeast-1",   # Japan (Tokyo)
    "ap-southeast-1",   # Singapore
    "ap-southeast-2",   # Australia (Sydney)
    "ap-southeast-3",   # Malaysia (Kuala Lumpur)
    "ap-southeast-5",   # Indonesia (Jakarta)
    "ap-southeast-6",   # Philippines (Manila)
    "ap-southeast-7",   # Thailand (Bangkok)
    "ap-south-1",       # India (Mumbai)
    "us-west-1",        # US (Silicon Valley)
    "us-east-1",        # US (Virginia)
    "eu-west-1",        # UK (London)
    "eu-central-1",     # Germany (Frankfurt)
    "me-east-1",        # UAE (Dubai)
]

# Alibaba Cloud SDK configuration
ALIBABACLOUD_SDK_USER_AGENT = "Prowler"
ALIBABACLOUD_SDK_MAX_RETRIES = 3
ALIBABACLOUD_SDK_TIMEOUT = 30  # seconds

# Alibaba Cloud ARN format
ALIBABACLOUD_ARN_FORMAT = "acs:{service}:{region}:{account_id}:{resource}"

# Default RAM role session name
ALIBABACLOUD_RAM_SESSION_NAME = "ProwlerSession"
