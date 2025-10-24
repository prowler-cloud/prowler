"""
Alibaba Cloud Provider Models

This module contains data models for the Alibaba Cloud provider.
"""

from argparse import Namespace
from dataclasses import dataclass
from typing import Optional

from prowler.providers.common.models import ProviderOutputOptions


@dataclass
class AlibabaCloudIdentityInfo:
    """
    AlibabaCloudIdentityInfo contains the Alibaba Cloud identity information

    Attributes:
        account_id: Alibaba Cloud account ID
        account_arn: Alibaba Cloud account ARN
        user_id: RAM user ID (optional)
        user_name: RAM user name (optional)
        account_name: Account alias/name (optional)
    """
    account_id: str
    account_arn: str
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    account_name: Optional[str] = None


@dataclass
class AlibabaCloudRegion:
    """
    AlibabaCloudRegion contains region information

    Attributes:
        region_id: Region identifier (e.g., "cn-hangzhou")
        local_name: Localized region name
        region_endpoint: Region endpoint URL
    """
    region_id: str
    local_name: str
    region_endpoint: Optional[str] = None


@dataclass
class AlibabaCloudCredentials:
    """
    AlibabaCloudCredentials contains authentication credentials

    Attributes:
        access_key_id: AccessKey ID
        access_key_secret: AccessKey Secret
        security_token: STS security token (optional)
        expiration: Token expiration timestamp (optional)
    """
    access_key_id: str
    access_key_secret: str
    security_token: Optional[str] = None
    expiration: Optional[str] = None


@dataclass
class AlibabaCloudAssumeRoleInfo:
    """
    AlibabaCloudAssumeRoleInfo contains RAM role assumption information

    Attributes:
        role_arn: RAM role ARN to assume
        role_session_name: Session name for the assumed role
        external_id: External ID for role assumption (optional)
        session_duration: Duration in seconds (900-43200, default 3600)
    """
    role_arn: str
    role_session_name: str
    external_id: Optional[str] = None
    session_duration: int = 3600


@dataclass
class AlibabaCloudSession:
    """
    AlibabaCloudSession contains the session configuration

    Attributes:
        credentials: Alibaba Cloud credentials
        region_id: Default region for the session
    """
    credentials: AlibabaCloudCredentials
    region_id: str = "cn-hangzhou"


class AlibabaCloudOutputOptions(ProviderOutputOptions):
    """
    AlibabaCloudOutputOptions contains the output configuration for Alibaba Cloud

    This class extends ProviderOutputOptions to provide Alibaba Cloud-specific
    output filename generation based on the account ID.
    """

    def __init__(self, arguments: Namespace, bulk_checks_metadata: dict, identity: AlibabaCloudIdentityInfo):
        """
        Initialize Alibaba Cloud output options

        Args:
            arguments: Command-line arguments
            bulk_checks_metadata: Metadata for all checks
            identity: Alibaba Cloud identity information
        """
        # Call parent class init
        super().__init__(arguments, bulk_checks_metadata)

        # Import here to avoid circular dependency
        from prowler.config.config import output_file_timestamp

        # Check if custom output filename was provided
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            # Use account ID for output filename
            account_identifier = identity.account_id
            self.output_filename = (
                f"prowler-output-{account_identifier}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
