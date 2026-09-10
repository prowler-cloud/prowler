"""Huawei Cloud Provider Models"""

from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic.v1 import BaseModel, validator

from prowler.lib.logger import logger
from prowler.providers.common.models import ProviderOutputOptions
from prowler.providers.huaweicloud.config import (
    HUAWEICLOUD_DEFAULT_REGION,
    HUAWEICLOUD_SDK_CONNECT_TIMEOUT,
    HUAWEICLOUD_SDK_READ_TIMEOUT,
)
from prowler.providers.huaweicloud.exceptions.exceptions import (
    HuaweiCloudServiceError,
)


def _iam_endpoint_for_region(region: str):
    """Return the IAM endpoint for a region, or None if unknown.

    Huawei Cloud runs separate clouds per TLD (International .com, Europe .eu,
    China). The region-specific IAM endpoint (e.g. iam.eu-west-101.myhuawei
    cloud.eu) is the only one that recognizes that cloud's accounts, so it must
    be used for credential validation and per-region project resolution.
    """
    try:
        from huaweicloudsdkiam.v3.region.iam_region import IamRegion

        return IamRegion.value_of(region).endpoints[0]
    except Exception:
        return None


def _endpoint_host(endpoint: str) -> str:
    """Return the lowercased host of an endpoint URL, or "" if unparseable.

    Used so cloud detection matches on the URL host's TLD suffix instead of an
    arbitrary substring, which avoids being fooled by a lookalike host such as
    ``iam.myhuaweicloud.com.example.eu``.
    """
    if not endpoint:
        return ""
    parsed = urlparse(endpoint if "://" in endpoint else f"//{endpoint}")
    return (parsed.hostname or "").lower()


def _align_endpoint_tld(region: str, endpoint: str) -> str:
    """Align a service endpoint's TLD to the region's cloud.

    The cloud a region belongs to (International/China on .com, Europe on .eu)
    is a property of the region, and IAM is authoritative for it. Some Huawei
    Cloud services still ship the .com endpoint for Europe (.eu) regions in
    their bundled region metadata (e.g. ECS/VPC/ELB/EVS/WAF for eu-west-101),
    which rejects .eu accounts with InvalidAccessKeyId. Rewrite the TLD to
    match the region's IAM endpoint so every service targets the right cloud.
    """
    iam_endpoint = _iam_endpoint_for_region(region)
    if not iam_endpoint or not endpoint:
        return endpoint
    iam_host = _endpoint_host(iam_endpoint)
    if iam_host.endswith(".myhuaweicloud.eu"):
        return endpoint.replace(".myhuaweicloud.com", ".myhuaweicloud.eu")
    if iam_host.endswith(".myhuaweicloud.com"):
        return endpoint.replace(".myhuaweicloud.eu", ".myhuaweicloud.com")
    return endpoint


def _aligned_region(region_cls, region_id: str):
    """Return the service Region for ``region_id`` with a cloud-aligned endpoint.

    Uses the service's own region metadata, but corrects the endpoint TLD when
    the service lags behind the region's actual cloud (see _align_endpoint_tld).
    Returns the unmodified region object when no correction is needed.
    """
    sdk_region = region_cls.value_of(region_id)
    endpoint = sdk_region.endpoints[0]
    aligned = _align_endpoint_tld(region_id, endpoint)
    if aligned == endpoint:
        return sdk_region
    from huaweicloudsdkcore.region.region import Region

    return Region(region_id, aligned)


class HuaweiCloudBaseModel(BaseModel):
    """Base model for Huawei Cloud service resources.

    The Huawei Cloud SDK regularly returns optional attributes explicitly set
    to None. Passing None to a non-optional ``str`` field (whether required or
    with a default) raises a pydantic ValidationError, so coerce those None
    values to the field's default (an empty string) before validation.
    ``Optional[...]`` fields keep accepting None.
    """

    @validator("*", pre=True)
    def _coerce_none_for_non_optional_str(cls, value, field):  # noqa: vulture
        if value is None and not field.allow_none and field.type_ is str:
            return field.default if field.default is not None else ""
        return value


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
        domain_id: The Huawei Cloud domain ID
        expiration: The expiration time for temporary credentials
    """

    ak: str
    sk: str
    security_token: Optional[str] = None
    domain_id: Optional[str] = None
    expiration: Optional[datetime] = None


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

    def __init__(
        self,
        credentials: HuaweiCloudCredentials,
        region: str = None,
    ):
        """
        Initialize the Huawei Cloud session.

        Args:
            credentials: The Huawei Cloud credentials
            region: The default region for the session
        """
        self._credentials = credentials
        self._region = region or HUAWEICLOUD_DEFAULT_REGION
        self._regional_clients = {}

    @property
    def credentials(self) -> HuaweiCloudCredentials:
        """Get the Huawei Cloud credentials."""
        return self._credentials

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
                from huaweicloudsdkobs.v1.obs_credentials import ObsCredentials
                from huaweicloudsdkobs.v1.region.obs_region import ObsRegion

                client_region = region or self._region
                obs_creds = ObsCredentials(
                    ak=self._credentials.ak,
                    sk=self._credentials.sk,
                    securityToken=getattr(self._credentials, "security_token", None),
                )
                return (
                    ObsClient.new_builder()
                    .with_credentials(obs_creds)
                    .with_http_config(self._http_config())
                    .with_region(ObsRegion.value_of(client_region))
                    .build()
                )

            elif service == "ecs":
                from huaweicloudsdkecs.v2 import EcsClient
                from huaweicloudsdkecs.v2.region.ecs_region import EcsRegion

                client_region = region or self._region
                return (
                    EcsClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(EcsRegion, client_region))
                    .build()
                )

            elif service == "vpc":
                from huaweicloudsdkvpc.v2 import VpcClient
                from huaweicloudsdkvpc.v2.region.vpc_region import VpcRegion

                client_region = region or self._region
                return (
                    VpcClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(VpcRegion, client_region))
                    .build()
                )

            elif service == "iam":
                from huaweicloudsdkiam.v3 import IamClient
                from huaweicloudsdkiam.v3.region.iam_region import IamRegion

                # IAM is a global service, but we still need a region for the client
                client_region = region or self._region
                return (
                    IamClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(IamRegion, client_region))
                    .build()
                )

            elif service == "rds":
                from huaweicloudsdkrds.v3 import RdsClient
                from huaweicloudsdkrds.v3.region.rds_region import RdsRegion

                client_region = region or self._region
                return (
                    RdsClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(RdsRegion, client_region))
                    .build()
                )

            elif service == "cts":
                from huaweicloudsdkcts.v3 import CtsClient
                from huaweicloudsdkcts.v3.region.cts_region import CtsRegion

                client_region = region or self._region
                return (
                    CtsClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(CtsRegion, client_region))
                    .build()
                )

            elif service == "kms":
                from huaweicloudsdkkms.v2 import KmsClient
                from huaweicloudsdkkms.v2.region.kms_region import KmsRegion

                client_region = region or self._region
                return (
                    KmsClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(KmsRegion, client_region))
                    .build()
                )

            elif service == "waf":
                from huaweicloudsdkwaf.v1 import WafClient
                from huaweicloudsdkwaf.v1.region.waf_region import WafRegion

                client_region = region or self._region
                return (
                    WafClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(WafRegion, client_region))
                    .build()
                )

            elif service == "elb":
                from huaweicloudsdkelb.v3 import ElbClient
                from huaweicloudsdkelb.v3.region.elb_region import ElbRegion

                client_region = region or self._region
                return (
                    ElbClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(ElbRegion, client_region))
                    .build()
                )

            elif service == "evs":
                from huaweicloudsdkevs.v2 import EvsClient
                from huaweicloudsdkevs.v2.region.evs_region import EvsRegion

                client_region = region or self._region
                return (
                    EvsClient.new_builder()
                    .with_credentials(self._get_basic_credentials(client_region))
                    .with_http_config(self._http_config())
                    .with_region(_aligned_region(EvsRegion, client_region))
                    .build()
                )

            else:
                raise HuaweiCloudServiceError(
                    message=f"Huawei Cloud service '{service}' is not supported"
                )

        except HuaweiCloudServiceError:
            raise
        except ImportError as e:
            logger.error(
                f"Failed to import Huawei Cloud SDK for service '{service}': {e}"
            )
            raise
        except Exception as e:
            logger.error(
                f"Failed to create Huawei Cloud client for service '{service}': {e}"
            )
            raise

    @staticmethod
    def _http_config():
        """Build an HttpConfig with the provider's connect/read timeouts."""
        from huaweicloudsdkcore.http.http_config import HttpConfig

        config = HttpConfig.get_default_config()
        config.timeout = (
            HUAWEICLOUD_SDK_CONNECT_TIMEOUT,
            HUAWEICLOUD_SDK_READ_TIMEOUT,
        )
        return config

    def _get_basic_credentials(self, region: str = None):
        """Get Huawei Cloud BasicCredentials from stored credentials.

        The project_id is intentionally left unset: the SDK resolves the
        correct project_id for each region automatically (cached per region),
        which is required for multi-region scans since each region has its own
        project. Pinning a single project_id would break every other region.

        Args:
            region: The region the resulting client targets. Defaults to the
                session's region. It selects the IAM endpoint used for project
                auto-resolution, so multi-region scans point each regional
                client at its own region's endpoint.
        """
        from huaweicloudsdkcore.auth.credentials import BasicCredentials

        creds = self._credentials

        basic_creds = BasicCredentials(ak=creds.ak, sk=creds.sk)

        # Point the SDK's per-region project auto-resolution at the region's
        # own IAM endpoint. It otherwise defaults to the .com (International)
        # global endpoint, which rejects Huawei Cloud Europe (.eu) accounts.
        iam_endpoint = _iam_endpoint_for_region(region or self._region)
        if iam_endpoint:
            basic_creds.iam_endpoint = iam_endpoint

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
