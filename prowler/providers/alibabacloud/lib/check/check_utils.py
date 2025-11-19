"""Utility classes for Alibaba Cloud checks"""

from dataclasses import dataclass


@dataclass
class GenericAlibabaCloudResource:
    """Generic resource for checks that don't have a specific resource type"""

    id: str
    name: str
    arn: str
    region: str
