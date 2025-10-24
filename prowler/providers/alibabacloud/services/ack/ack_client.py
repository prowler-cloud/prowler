"""Alibaba Cloud ACK Client Singleton"""

from prowler.providers.alibabacloud.services.ack.ack_service import ACK
from prowler.providers.common.provider import Provider

ack_client = ACK(Provider.get_global_provider())
