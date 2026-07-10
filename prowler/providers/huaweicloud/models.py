"""Huawei Cloud Provider Models"""

from datetime import datetime
from typing import Any, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.common.models import ProviderOutputOptions
from prowler.providers.huaweicloud.config import (
    HUAWEICLOUD_DEFAULT_REGION,
)


class HuaweiCloudCallerIdentity(BaseModel):
    """
    HuaweiCloudCallerIdentity stores the caller identity information from IAM.
    
    Attributes:
        domain_id: The Huawei Cloud domain ID
        user_id: The Huawei Cloud user ID
        user_name: The Huawei Cloud user name
        account_id: The Huawei Cloud account ID (same as domain_id for most cases)
        account_name: The Huawei Cloud account name
        type: The type of identity (e.g., "user", "agency", "token")
    """

    domain_id: str
    user_id: str
    user_name: str
    account_id: str
    account_name: str
    type: str = "user"


class HuaweiCloudIdentityInfo(BaseModel):
    """
    HuaweiCloudIdentityInfo stores the Huawei Cloud account identity information.
    
    Attributes:
        account_id: The Huawei Cloud account ID
        account_name: The Huawei Cloud account name
        domain_id: The Huawei Cloud domain ID
        user_id: The Huawei Cloud user ID
        user_name: The Huawei Cloud user name
        identity_type: The type of identity (e.g., "user", "agency", "token")
        regions: Set of regions to be audited
        profile: The profile name used for authentication
        profile_region: The default region from the profile
    """

    account_id: str
    account_name: str
    domain_id: str
    user_id: str
    user_name: str
    identity_type: str = "user"
    regions: set[str]
    profile: Optional[str] = None
    profile_region: Optional[str] = None


class HuaweiCloudCredentials(BaseModel):
    """
    HuaweiCloudCredentials stores the Huawei Cloud credentials.
    
    Attributes:
        ak: The Access Key ID
        sk: The Secret Access Key
        security_token: The Security Token (for temporary credentials)
        project_id: The Huawei Cloud project ID (required for regional services)
        domain_id: The Huawei Cloud domain ID
        expiration: The expiration time for temporary credentials
    """

    ak: str
    sk: str
    security_token: Optional[str] = None
    project_id: Optional[str] = None
    domain_id: Optional[str] = None
    expiration: Optional[datetime] = None


class HuaweiCloudAssumeRoleInfo(BaseModel):
    """
    HuaweiCloudAssumeRoleInfo stores the information for assuming an agency (role).
    
    Attributes:
        agency_name: The name of the agency to assume
        domain_id: The domain ID of the delegating account
        delegation_domain_id: The domain ID of the delegated account
        session_duration: The duration of the assumed agency session (in seconds)
        session_name: The session name for the assumed agency
    """

    agency_name: str
    domain_id: str
    delegation_domain_id: str
    session_duration: int = 3600  # Default 1 hour
    session_name: str = "ProwlerAssessmentSession"


class HuaweiCloudRegion(BaseModel):
    """
    HuaweiCloudRegion stores information about a Huawei Cloud region.
    
    Attributes:
        region_id: The region identifier (e.g., cn-north-4, ap-southeast-1)
        region_name: The human-readable region name
        region_endpoint: The API endpoint for the region
    """

    region_id: str
    region_name: str
    region_endpoint: Optional[str] = None


class HuaweiCloudSession:
    """
    HuaweiCloudSession stores the Huawei Cloud session and credentials.
    
    This class provides methods to get credentials and create service clients.
    """
    
    def __init__(self, credentials: HuaweiCloudCredentials, region: str = None, is_mock: bool = False):
        """
        Initialize the Huawei Cloud session.
        
        Args:
            credentials: The Huawei Cloud credentials
            region: The default region for the session
            is_mock: Whether this is a mock session (no real API calls)
        """
        self._credentials = credentials
        self._region = region or HUAWEICLOUD_DEFAULT_REGION
        self._regional_clients = {}
        self._is_mock = is_mock
        
    @property
    def credentials(self) -> HuaweiCloudCredentials:
        """Get the Huawei Cloud credentials."""
        return self._credentials
    
    @property
    def is_mock(self) -> bool:
        """Check if this is a mock session."""
        return self._is_mock

    @property
    def region(self) -> str:
        """Get the default region."""
        return self._region
    
    @region.setter
    def region(self, value: str):
        """Set the default region."""
        self._region = value
    
    def get_credentials(self) -> HuaweiCloudCredentials:
        """
        Get the Huawei Cloud credentials.
        
        Returns:
            HuaweiCloudCredentials object
        """
        return self._credentials
    
    def client(self, service: str, region: str = None) -> Any:
        """
        Create a service client for the given service and region.
        
        Args:
            service: The service name (e.g., 'ecs', 'vpc', 'obs')
            region: The region (optional, some services are global)
            
        Returns:
            A client instance for the specified service
            
        Raises:
            HuaweiCloudServiceError: If the service is not supported
        """
        # Import Huawei Cloud SDK dynamically based on service
        try:
            if service == "obs":
                from huaweicloudsdkobs.v1 import ObsClient
                from huaweicloudsdkobs.v1.region.obs_region import ObsRegion
                from huaweicloudsdkobs.v1.obs_credentials import ObsCredentials

                client_region = region or self._region
                obs_creds = ObsCredentials(
                    ak=self._credentials.ak,
                    sk=self._credentials.sk,
                    securityToken=getattr(self._credentials, "security_token", None),
                )
                return ObsClient.new_builder() \
                    .with_credentials(obs_creds) \
                    .with_region(ObsRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "ecs":
                from huaweicloudsdkecs.v2 import EcsClient
                from huaweicloudsdkecs.v2.region.ecs_region import EcsRegion
                
                client_region = region or self._region
                return EcsClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(EcsRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "vpc":
                from huaweicloudsdkvpc.v2 import VpcClient
                from huaweicloudsdkvpc.v2.region.vpc_region import VpcRegion
                
                client_region = region or self._region
                return VpcClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(VpcRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "iam":
                from huaweicloudsdkiam.v3 import IamClient
                from huaweicloudsdkiam.v3.region.iam_region import IamRegion
                
                # IAM is a global service, but we still need a region for the client
                client_region = region or self._region
                return IamClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(IamRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "rds":
                from huaweicloudsdkrds.v3 import RdsClient
                from huaweicloudsdkrds.v3.region.rds_region import RdsRegion
                
                client_region = region or self._region
                return RdsClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(RdsRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "cts":
                from huaweicloudsdkcts.v3 import CtsClient
                from huaweicloudsdkcts.v3.region.cts_region import CtsRegion
                
                client_region = region or self._region
                return CtsClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(CtsRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "kms":
                from huaweicloudsdkkms.v2 import KmsClient
                from huaweicloudsdkkms.v2.region.kms_region import KmsRegion
                
                client_region = region or self._region
                return KmsClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(KmsRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "waf":
                from huaweicloudsdkwaf.v1 import WafClient
                from huaweicloudsdkwaf.v1.region.waf_region import WafRegion
                
                client_region = region or self._region
                return WafClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(WafRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "elb":
                from huaweicloudsdkelb.v3 import ElbClient
                from huaweicloudsdkelb.v3.region.elb_region import ElbRegion
                
                client_region = region or self._region
                return ElbClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(ElbRegion.value_of(client_region)) \
                    .build()
                    
            elif service == "evs":
                from huaweicloudsdkevs.v2 import EvsClient
                from huaweicloudsdkevs.v2.region.evs_region import EvsRegion
                
                client_region = region or self._region
                return EvsClient.new_builder() \
                    .with_credentials(self._get_basic_credentials()) \
                    .with_region(EvsRegion.value_of(client_region)) \
                    .build()
                    
            else:
                logger.warning(f"Huawei Cloud service '{service}' not yet implemented")
                return None
                
        except ImportError as e:
            logger.error(f"Failed to import Huawei Cloud SDK for service '{service}': {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to create Huawei Cloud client for service '{service}': {e}")
            raise
    
    def _get_basic_credentials(self):
        """Get Huawei Cloud BasicCredentials from stored credentials."""
        from huaweicloudsdkcore.auth.credentials import BasicCredentials
        
        creds = self._credentials

        # Create BasicCredentials with AK/SK
        # BasicCredentials only accepts ak, sk, project_id in __init__
        basic_creds = BasicCredentials(
            ak=creds.ak,
            sk=creds.sk,
            project_id=creds.project_id,
        )

        # security_token is a settable property (for temporary credentials)
        if creds.security_token:
            basic_creds.security_token = creds.security_token

        return basic_creds


class HuaweiCloudOutputOptions(ProviderOutputOptions):
    """
    HuaweiCloudOutputOptions extends ProviderOutputOptions for Huawei Cloud specific output options.
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
