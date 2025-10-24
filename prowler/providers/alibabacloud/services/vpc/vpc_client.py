"""Alibaba Cloud VPC Client Singleton"""

from prowler.providers.alibabacloud.services.vpc.vpc_service import VPC_Service
from prowler.providers.common.provider import Provider

vpc_client = VPC_Service(Provider.get_global_provider())
