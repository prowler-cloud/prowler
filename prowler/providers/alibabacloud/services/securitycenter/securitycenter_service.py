"""Alibaba Cloud Security Center Service"""

from dataclasses import dataclass
from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class SecurityCenterConfig:
    """Security Center Configuration"""
    enabled: bool = False  # Will trigger check
    version: str = "Basic"  # Should be "Advanced" or "Enterprise"
    anti_ransomware: bool = False  # Will trigger check
    threat_detection: bool = False  # Will trigger check
    vulnerability_scan: bool = False  # Will trigger check

class SecurityCenter(AlibabaCloudService):
    def __init__(self, provider):
        super().__init__("securitycenter", provider)
        self.config = SecurityCenterConfig(
            enabled=False,
            version="Basic",
            anti_ransomware=False,
            threat_detection=False,
            vulnerability_scan=False
        )
        logger.info(f"Security Center initialized")
