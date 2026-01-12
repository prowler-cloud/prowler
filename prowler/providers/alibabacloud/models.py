from datetime import datetime
from typing import Optional

from alibabacloud_actiontrail20200706.client import Client as ActionTrailClient
from alibabacloud_cs20151215.client import Client as CSClient
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_oss20190517.client import Client as OssClient
from alibabacloud_ram20150501.client import Client as RamClient
from alibabacloud_rds20140815.client import Client as RdsClient
from alibabacloud_sas20181203.client import Client as SasClient
from alibabacloud_sls20201230.client import Client as SlsClient
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_vpc20160428.client import Client as VpcClient
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.config import (
    ALIBABACLOUD_DEFAULT_REGION,
    ALIBABACLOUD_SDK_CONNECT_TIMEOUT,
    ALIBABACLOUD_SDK_READ_TIMEOUT,
)
from prowler.providers.common.models import ProviderOutputOptions


class AlibabaCloudCallerIdentity(BaseModel):
    """
    AlibabaCloudCallerIdentity stores the caller identity information from STS GetCallerIdentity.

    Attributes:
        account_id: The Alibaba Cloud account ID
        principal_id: The principal ID (user ID or root account ID)
        arn: The ARN-like identifier for the identity
        identity_type: The type of identity (e.g., "RamUser", "Root")
    """

    account_id: str
    principal_id: str
    arn: str
    identity_type: str = ""


class AlibabaCloudIdentityInfo(BaseModel):
    """
    AlibabaCloudIdentityInfo stores the Alibaba Cloud account identity information.

    Attributes:
        account_id: The Alibaba Cloud account ID
        account_name: The Alibaba Cloud account name (if available)
        user_id: The RAM user ID or root account ID
        user_name: The RAM user name or "root" for root account
        identity_arn: The ARN-like identifier for the identity
        profile: The profile name used for authentication
        profile_region: The default region from the profile
        audited_regions: Set of regions to be audited
        is_root: Whether this is the root account (True) or a RAM user (False)
    """

    account_id: str
    account_name: str
    user_id: str
    user_name: str
    identity_arn: str
    profile: str
    profile_region: str
    audited_regions: set[str]
    is_root: bool = False


class AlibabaCloudCredentials(BaseModel):
    """
    AlibabaCloudCredentials stores the Alibaba Cloud credentials.

    Attributes:
        access_key_id: The Access Key ID
        access_key_secret: The Access Key Secret
        security_token: The Security Token (for STS temporary credentials)
        expiration: The expiration time for temporary credentials
    """

    access_key_id: str
    access_key_secret: str
    security_token: Optional[str] = None
    expiration: Optional[datetime] = None


class AlibabaCloudAssumeRoleInfo(BaseModel):
    """
    AlibabaCloudAssumeRoleInfo stores the information for assuming a RAM role.

    Attributes:
        role_arn: The ARN of the role to assume
        role_session_name: The session name for the assumed role
        session_duration: The duration of the assumed role session (in seconds)
        external_id: The external ID for role assumption
        region: The region for STS endpoint
    """

    role_arn: str
    role_session_name: str
    session_duration: int
    external_id: Optional[str] = None
    region: str = "cn-hangzhou"


class AlibabaCloudRegion(BaseModel):
    """
    AlibabaCloudRegion stores information about an Alibaba Cloud region.

    Attributes:
        region_id: The region identifier (e.g., cn-hangzhou, cn-shanghai)
        region_name: The human-readable region name
        region_endpoint: The API endpoint for the region
    """

    region_id: str
    region_name: str
    region_endpoint: Optional[str] = None


class AlibabaCloudSession:
    """
    AlibabaCloudSession stores the Alibaba Cloud session and credentials.

    This class provides methods to get credentials and create service clients.
    """

    def __init__(self, cred_client):
        """
        Initialize the Alibaba Cloud session.

        Args:
            cred_client: The Alibaba Cloud credentials client
        """
        self.cred_client = cred_client
        self._credentials = None

    def get_credentials(self):
        """
        Get the Alibaba Cloud credentials.

        Returns:
            AlibabaCloudCredentials object
        """
        if self._credentials is None:
            cred = self.cred_client.get_credential()
            self._credentials = AlibabaCloudCredentials(
                access_key_id=cred.get_access_key_id(),
                access_key_secret=cred.get_access_key_secret(),
                security_token=cred.get_security_token(),
            )
        return self._credentials

    def client(self, service: str, region: str = None):
        """
        Create a service client for the given service and region.

        Args:
            service: The service name (e.g., 'ram')
            region: The region (optional, some services are global)

        Returns:
            A client instance for the specified service
        """

        # Get credentials
        cred = self.get_credentials()

        # Create client configuration with timeout settings
        config = open_api_models.Config(
            access_key_id=cred.access_key_id,
            access_key_secret=cred.access_key_secret,
            read_timeout=ALIBABACLOUD_SDK_READ_TIMEOUT
            * 1000,  # Convert to milliseconds
            connect_timeout=ALIBABACLOUD_SDK_CONNECT_TIMEOUT
            * 1000,  # Convert to milliseconds
        )
        if cred.security_token:
            config.security_token = cred.security_token

        # Set endpoint based on service
        if service == "ram":
            config.endpoint = "ram.aliyuncs.com"
            return RamClient(config)
        elif service == "vpc":
            # VPC endpoint is regional: vpc.{region}.aliyuncs.com
            if region:
                config.endpoint = f"vpc.{region}.aliyuncs.com"
            else:
                config.endpoint = f"vpc.{ALIBABACLOUD_DEFAULT_REGION}.aliyuncs.com"
            return VpcClient(config)
        elif service == "ecs":
            # ECS endpoint is regional: ecs.{region}.aliyuncs.com
            if region:
                config.endpoint = f"ecs.{region}.aliyuncs.com"
            else:
                config.endpoint = f"ecs.{ALIBABACLOUD_DEFAULT_REGION}.aliyuncs.com"
            return EcsClient(config)
        elif service == "sas" or service == "securitycenter":
            # SAS (Security Center) endpoint is regional: sas.{region}.aliyuncs.com
            if region:
                config.endpoint = f"sas.{region}.aliyuncs.com"
            else:
                config.endpoint = f"sas.{ALIBABACLOUD_DEFAULT_REGION}.aliyuncs.com"
            return SasClient(config)
        elif service == "oss":
            if region:
                config.endpoint = f"oss-{region}.aliyuncs.com"
                config.region_id = region
            else:
                config.endpoint = f"oss-{ALIBABACLOUD_DEFAULT_REGION}.aliyuncs.com"
                config.region_id = ALIBABACLOUD_DEFAULT_REGION
            return OssClient(config)
        elif service == "actiontrail":
            # ActionTrail endpoint is regional: actiontrail.{region}.aliyuncs.com
            if region:
                config.endpoint = f"actiontrail.{region}.aliyuncs.com"
            else:
                config.endpoint = (
                    f"actiontrail.{ALIBABACLOUD_DEFAULT_REGION}.aliyuncs.com"
                )
            return ActionTrailClient(config)
        elif service == "cs":
            if region:
                config.endpoint = f"cs.{region}.aliyuncs.com"
            else:
                config.endpoint = f"cs.{ALIBABACLOUD_DEFAULT_REGION}.aliyuncs.com"
            return CSClient(config)
        elif service == "rds":
            if region:
                config.endpoint = f"rds.{region}.aliyuncs.com"
            else:
                config.endpoint = f"rds.{ALIBABACLOUD_DEFAULT_REGION}.aliyuncs.com"
            return RdsClient(config)
        elif service == "sls":
            if region:
                config.endpoint = f"{region}.log.aliyuncs.com"
            else:
                config.endpoint = f"{ALIBABACLOUD_DEFAULT_REGION}.log.aliyuncs.com"
            return SlsClient(config)
        else:
            # For other services, implement as needed
            logger.warning(f"Service {service} not yet implemented")
            return None


class AlibabaCloudOutputOptions(ProviderOutputOptions):
    """
    AlibabaCloudOutputOptions extends ProviderOutputOptions for Alibaba Cloud specific output options.
    """

    def __init__(self, arguments, bulk_checks_metadata, identity):
        # Call parent class init
        super().__init__(arguments, bulk_checks_metadata)

        # Set default output filename if not provided
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            from prowler.config.config import output_file_timestamp

            self.output_filename = (
                f"prowler-output-{identity.account_id}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
