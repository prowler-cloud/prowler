"""Alibaba Cloud Provider Configuration Constants"""

ALIBABACLOUD_DEFAULT_REGION = "cn-hangzhou"
ROLE_SESSION_NAME = "ProwlerAssessmentSession"

# Alibaba Cloud SDK Configuration
ALIBABACLOUD_SDK_READ_TIMEOUT = 60  # seconds
ALIBABACLOUD_SDK_CONNECT_TIMEOUT = 10  # seconds

# Alibaba Cloud Regions - Only publicly accessible regions
# Note: Some regions may require special approval or are not globally available
ALIBABACLOUD_REGIONS = {
    # China Regions
    "cn-qingdao": "China (Qingdao)",
    "cn-beijing": "China (Beijing)",
    "cn-zhangjiakou": "China (Zhangjiakou)",
    "cn-huhehaote": "China (Hohhot)",
    "cn-wulanchabu": "China (Ulanqab)",
    "cn-hangzhou": "China (Hangzhou)",
    "cn-shanghai": "China (Shanghai)",
    "cn-shenzhen": "China (Shenzhen)",
    "cn-heyuan": "China (Heyuan)",
    "cn-guangzhou": "China (Guangzhou)",
    "cn-chengdu": "China (Chengdu)",
    "cn-hongkong": "China (Hong Kong)",
    # Asia-Pacific Regions
    "ap-northeast-1": "Japan (Tokyo)",
    "ap-northeast-2": "South Korea (Seoul)",
    "ap-southeast-1": "Singapore",
    "ap-southeast-3": "Malaysia (Kuala Lumpur)",
    "ap-southeast-5": "Indonesia (Jakarta)",
    "ap-southeast-6": "Philippines (Manila)",
    "ap-southeast-7": "Thailand (Bangkok)",
    # US Regions
    "us-east-1": "US (Virginia)",
    "us-west-1": "US (Silicon Valley)",
    # Europe & Middle East Regions
    "eu-west-1": "UK (London)",
    "me-east-1": "UAE (Dubai)",
    "eu-central-1": "Germany (Frankfurt)",
}
