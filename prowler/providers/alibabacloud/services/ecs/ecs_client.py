"""
Alibaba Cloud ECS Client Singleton

This module provides the singleton ECS client instance.
"""

from prowler.providers.alibabacloud.services.ecs.ecs_service import ECS
from prowler.providers.common.provider import Provider

# Initialize ECS client singleton
ecs_client = ECS(Provider.get_global_provider())
