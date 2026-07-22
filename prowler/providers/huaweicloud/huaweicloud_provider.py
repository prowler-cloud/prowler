import os
import pathlib

from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.config import (
    HUAWEICLOUD_DEFAULT_REGION,
    HUAWEICLOUD_REGIONS,
)
from prowler.providers.huaweicloud.exceptions.exceptions import (
    HuaweiCloudAssumeRoleError,
    HuaweiCloudAuthenticationError,
    HuaweiCloudCredentialsError,
    HuaweiCloudIdentityError,
    HuaweiCloudInvalidProviderIdError,
    HuaweiCloudInvalidRegionError,
    HuaweiCloudSetUpSessionError,
)
from prowler.providers.huaweicloud.lib.mutelist.mutelist import HuaweiCloudMutelist
from prowler.providers.huaweicloud.models import (
    HuaweiCloudCallerIdentity,
    HuaweiCloudCredentials,
    HuaweiCloudIdentityInfo,
    HuaweiCloudSession,
    _iam_endpoint_for_region,
)


class HuaweicloudProvider(Provider):
    """
    HuaweicloudProvider class is the main class for the Huawei Cloud provider.

    This class is responsible for initializing the Huawei Cloud provider, setting up the session,
    validating the credentials, and setting the identity.

    Attributes:
        _type (str): The provider type.
        _identity (HuaweiCloudIdentityInfo): The Huawei Cloud provider identity information.
        _session (HuaweiCloudSession): The Huawei Cloud provider session.
        _audit_resources (list): The list of resources to audit.
        _audit_config (dict): The audit configuration.
        _enabled_regions (set): The set of enabled regions.
        _mutelist (HuaweiCloudMutelist): The Huawei Cloud provider mutelist.
        audit_metadata (Audit_Metadata): The audit metadata.
    """

    _type: str = "huaweicloud"
    _identity: HuaweiCloudIdentityInfo
    _session: HuaweiCloudSession
    _audit_resources: list = []
    _audit_config: dict
    _fixer_config: dict
    _regions: list = []
    _mutelist: HuaweiCloudMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        access_key_id: str = None,
        secret_access_key: str = None,
        domain_id: str = None,
        security_token: str = None,
        agency_name: str = None,
        assume_domain_id: str = None,
        assume_domain_name: str = None,
        cloud: str = None,
        regions: list = None,
        config_path: str = None,
        config_content: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        fixer_config: dict = {},
    ):
        """
        Initialize the HuaweicloudProvider.

        Credentials are read from environment variables. The credential
        arguments below exist for programmatic use only (they fall back to the
        environment variables when not provided) and are never populated from
        the CLI.

        Args:
            access_key_id: Huawei Cloud Access Key ID
            secret_access_key: Huawei Cloud Secret Access Key
            domain_id: Huawei Cloud Domain ID
            security_token: Security Token (for temporary credentials)
            agency_name: Name of the agency to assume in the target account
            assume_domain_id: Domain ID of the target (delegating) account
            assume_domain_name: Domain name of the target (delegating) account
            cloud: Huawei Cloud instance to scan (international, europe, china)
                when no explicit regions are given; expands to that cloud's regions
            regions: List of Huawei Cloud region IDs to audit
            config_path: Path to the configuration file
            config_content: Content of the configuration file
            mutelist_path: Path to the mutelist file
            mutelist_content: Content of the mutelist file
            fixer_config: Fixer configuration dictionary

        Raises:
            HuaweiCloudSetUpSessionError: If an error occurs during the setup process.
            HuaweiCloudAuthenticationError: If authentication fails.

        Usage:
            - Huawei Cloud credentials are set via environment variables:
                - export HUAWEICLOUD_ACCESS_KEY_ID=<access_key>
                - export HUAWEICLOUD_SECRET_ACCESS_KEY=<secret_key>
                - export HUAWEICLOUD_DOMAIN_ID=<domain_id>
              The per-region project_id is resolved automatically by the SDK.
            - To assume an agency in a target account, additionally set:
                - export HUAWEICLOUD_AGENCY_NAME=<agency_name>
                - export HUAWEICLOUD_ASSUME_DOMAIN_ID=<target_domain_id>
                  (or HUAWEICLOUD_ASSUME_DOMAIN_NAME=<target_domain_name>)
            - To create a new Huawei Cloud provider object:
                - huaweicloud = HuaweicloudProvider()
                - huaweicloud = HuaweicloudProvider(regions=["cn-north-4", "cn-east-3"])
        """
        logger.info("Initializing Huawei Cloud Provider ...")

        # The --region flag takes precedence; otherwise fall back to the
        # HUAWEICLOUD_REGION (or HW_REGION) env var, then the --cloud selector
        # (or HUAWEICLOUD_CLOUD), which expands to every region of that Huawei
        # Cloud instance so non-China accounts do not need to list regions.
        regions = self._resolve_regions(regions, cloud)

        logger.info("Setting up Huawei Cloud session ...")
        self._session = self.setup_session(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            domain_id=domain_id,
            security_token=security_token,
            agency_name=agency_name,
            assume_domain_id=assume_domain_id,
            assume_domain_name=assume_domain_name,
        )
        logger.info("Huawei Cloud session configured successfully")

        # Validate credentials against a region the account can actually reach.
        # The default (cn-north-4) is a China region that international accounts
        # cannot access, so honor the requested regions; the region must also
        # expose an IAM endpoint (some dedicated regions do not).
        validation_region = self._validation_region(regions)
        logger.info(f"Validating credentials in region {validation_region} ...")
        caller_identity = self.validate_credentials(
            session=self._session,
            region=validation_region,
        )
        logger.info("Credentials validated")

        profile_region = self.get_profile_region()

        self._identity = self.set_identity(
            caller_identity=caller_identity,
            profile="default",
            regions=set(),
            profile_region=profile_region,
        )

        self._regions = self.get_regions_to_audit(regions)

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = HuaweiCloudMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = HuaweiCloudMutelist(
                mutelist_path=mutelist_path,
            )

        self._audit_resources = []

        self.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        )

        Provider.set_global_provider(self)

    @property
    def type(self) -> str:
        return self._type

    @property
    def identity(self) -> HuaweiCloudIdentityInfo:
        return self._identity

    @property
    def session(self):
        return self._session

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    @property
    def audit_resources(self) -> list:
        return self._audit_resources

    @property
    def mutelist(self) -> HuaweiCloudMutelist:
        return self._mutelist

    @property
    def regions(self) -> list:
        return self._regions

    @property
    def enabled_regions(self) -> set:
        return set([r.region_id for r in self._regions])

    # Huawei Cloud runs separate clouds. International and China share the .com
    # endpoints (China regions are the cn-* ones); Europe uses the .eu
    # endpoints. An account belongs to a single cloud and can only reach that
    # cloud's regions.
    CLOUDS = ("international", "europe", "china")
    CLOUD_ALIASES = {
        "eu": "europe",
        "intl": "international",
        "com": "international",
        "cn": "china",
    }

    @staticmethod
    def _regions_for_cloud(cloud):
        """Return the region ids that belong to a Huawei Cloud instance.

        The cloud each region belongs to is derived from its IAM endpoint (.eu
        for Europe, .com otherwise) and the cn-* prefix (China), so the mapping
        stays accurate as the SDK's region list changes.
        """
        cloud = HuaweicloudProvider.CLOUD_ALIASES.get(cloud, cloud)
        result = []
        for region in HUAWEICLOUD_REGIONS:
            endpoint = _iam_endpoint_for_region(region) or ""
            is_europe = ".myhuaweicloud.eu" in endpoint
            is_china = region.startswith("cn-")
            if cloud == "europe" and is_europe:
                result.append(region)
            elif cloud == "china" and is_china:
                result.append(region)
            elif cloud == "international" and not is_europe and not is_china:
                result.append(region)
        return sorted(result)

    @staticmethod
    def _resolve_regions(regions, cloud=None):
        """Resolve the regions to audit.

        Precedence: the --region flag (``regions``) wins; then the
        HUAWEICLOUD_REGION (or HW_REGION) environment variable (one or more
        comma/space-separated region ids); then the --cloud selector (or
        HUAWEICLOUD_CLOUD / HW_CLOUD), which expands to every region of that
        Huawei Cloud instance.
        """
        if regions:
            return regions
        env_region = os.environ.get("HUAWEICLOUD_REGION") or os.environ.get("HW_REGION")
        if env_region:
            return env_region.replace(",", " ").split()
        cloud = (
            cloud or os.environ.get("HUAWEICLOUD_CLOUD") or os.environ.get("HW_CLOUD")
        )
        if cloud:
            cloud_regions = HuaweicloudProvider._regions_for_cloud(
                cloud.strip().lower()
            )
            if cloud_regions:
                return cloud_regions
        return regions

    @staticmethod
    def _validation_region(regions):
        """Pick a region to validate credentials against.

        Credential validation builds an IAM client, so the region must expose
        an IAM endpoint. Some Huawei Cloud regions (e.g. dedicated ones) are
        not in the IAM SDK; when only such regions are requested, validate
        against an IAM-capable region in the same cloud so the right endpoint
        is used.
        """
        if not regions:
            return HUAWEICLOUD_DEFAULT_REGION
        for region in sorted(regions):
            if _iam_endpoint_for_region(region):
                return region
        # None of the requested regions expose IAM. Fall back to an IAM-capable
        # region in the same cloud (inferred from the cn- prefix; Europe's only
        # region is IAM-capable, so it is already handled above).
        cloud = "china" if sorted(regions)[0].startswith("cn-") else "international"
        for region in HuaweicloudProvider._regions_for_cloud(cloud):
            if _iam_endpoint_for_region(region):
                return region
        return HUAWEICLOUD_DEFAULT_REGION

    @staticmethod
    def setup_session(
        access_key_id: str = None,
        secret_access_key: str = None,
        domain_id: str = None,
        security_token: str = None,
        agency_name: str = None,
        assume_domain_id: str = None,
        assume_domain_name: str = None,
    ) -> HuaweiCloudSession:
        """
        Set up the Huawei Cloud session.

        Each argument falls back to its environment variable when not provided.
        When an agency name is supplied (HUAWEICLOUD_AGENCY_NAME) the base
        credentials are used to assume the agency in the target account
        (HUAWEICLOUD_ASSUME_DOMAIN_ID or HUAWEICLOUD_ASSUME_DOMAIN_NAME) and the
        session uses the resulting temporary credentials.

        Args:
            access_key_id: Huawei Cloud Access Key ID
            secret_access_key: Huawei Cloud Secret Access Key
            domain_id: Huawei Cloud Domain ID
            security_token: Security Token (for temporary credentials)
            agency_name: Name of the agency to assume in the target account
            assume_domain_id: Domain ID of the target (delegating) account
            assume_domain_name: Domain name of the target (delegating) account

        Returns:
            HuaweiCloudSession object

        Raises:
            HuaweiCloudSetUpSessionError: If session setup fails
            HuaweiCloudCredentialsError: If no credentials are found
            HuaweiCloudAssumeRoleError: If assuming the agency fails
        """
        try:
            logger.debug("Creating Huawei Cloud session ...")

            if not access_key_id:
                if "HUAWEICLOUD_ACCESS_KEY_ID" in os.environ:
                    access_key_id = os.environ["HUAWEICLOUD_ACCESS_KEY_ID"]
                elif "HW_ACCESS_KEY" in os.environ:
                    access_key_id = os.environ["HW_ACCESS_KEY"]

            if not secret_access_key:
                if "HUAWEICLOUD_SECRET_ACCESS_KEY" in os.environ:
                    secret_access_key = os.environ["HUAWEICLOUD_SECRET_ACCESS_KEY"]
                elif "HW_SECRET_KEY" in os.environ:
                    secret_access_key = os.environ["HW_SECRET_KEY"]

            if not domain_id:
                if "HUAWEICLOUD_DOMAIN_ID" in os.environ:
                    domain_id = os.environ["HUAWEICLOUD_DOMAIN_ID"]
                elif "HW_DOMAIN_ID" in os.environ:
                    domain_id = os.environ["HW_DOMAIN_ID"]

            if not security_token and "HUAWEICLOUD_SECURITY_TOKEN" in os.environ:
                security_token = os.environ["HUAWEICLOUD_SECURITY_TOKEN"]

            if not agency_name:
                agency_name = os.environ.get("HUAWEICLOUD_AGENCY_NAME")
            if not assume_domain_id:
                assume_domain_id = os.environ.get("HUAWEICLOUD_ASSUME_DOMAIN_ID")
            if not assume_domain_name:
                assume_domain_name = os.environ.get("HUAWEICLOUD_ASSUME_DOMAIN_NAME")

            if not access_key_id or not secret_access_key:
                raise HuaweiCloudCredentialsError(
                    file=pathlib.Path(__file__).name,
                )

            credentials = HuaweiCloudCredentials(
                ak=access_key_id,
                sk=secret_access_key,
                security_token=security_token,
                domain_id=domain_id,
            )

            if agency_name:
                credentials = HuaweicloudProvider.assume_agency(
                    credentials=credentials,
                    agency_name=agency_name,
                    assume_domain_id=assume_domain_id,
                    assume_domain_name=assume_domain_name,
                )

            return HuaweiCloudSession(credentials)

        except (HuaweiCloudCredentialsError, HuaweiCloudAssumeRoleError):
            raise
        except Exception as error:
            logger.critical(
                f"HuaweiCloudSetUpSessionError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise HuaweiCloudSetUpSessionError(
                file=pathlib.Path(__file__).name,
                original_exception=error,
            )

    @staticmethod
    def assume_agency(
        credentials: HuaweiCloudCredentials,
        agency_name: str,
        assume_domain_id: str = None,
        assume_domain_name: str = None,
        region: str = HUAWEICLOUD_DEFAULT_REGION,
    ) -> HuaweiCloudCredentials:
        """
        Assume a Huawei Cloud agency in the target account.

        Uses the base credentials to call CreateTemporaryAccessKeyByAgency and
        returns temporary credentials scoped to the agency in the target
        (delegating) account.

        Args:
            credentials: The base Huawei Cloud credentials.
            agency_name: The agency to assume.
            assume_domain_id: Domain ID of the target (delegating) account.
            assume_domain_name: Domain name of the target (delegating) account.
            region: The region used for the IAM call.

        Returns:
            HuaweiCloudCredentials: Temporary credentials for the agency.

        Raises:
            HuaweiCloudAssumeRoleError: If the target account is not specified
                or the agency assumption fails.
        """
        if not assume_domain_id and not assume_domain_name:
            raise HuaweiCloudAssumeRoleError(
                file=pathlib.Path(__file__).name,
                message="To assume an agency, set HUAWEICLOUD_ASSUME_DOMAIN_ID or HUAWEICLOUD_ASSUME_DOMAIN_NAME to the target account.",
            )

        try:
            from huaweicloudsdkcore.auth.credentials import BasicCredentials
            from huaweicloudsdkiam.v3 import (
                AgencyAuth,
                AgencyAuthIdentity,
                CreateTemporaryAccessKeyByAgencyRequest,
                CreateTemporaryAccessKeyByAgencyRequestBody,
                IamClient,
                IdentityAssumerole,
            )
            from huaweicloudsdkiam.v3.region.iam_region import IamRegion

            basic_creds = BasicCredentials(
                ak=credentials.ak,
                sk=credentials.sk,
            )
            iam_endpoint = _iam_endpoint_for_region(region)
            if iam_endpoint:
                basic_creds.iam_endpoint = iam_endpoint
            if credentials.domain_id:
                basic_creds.domain_id = credentials.domain_id

            iam_client = (
                IamClient.new_builder()
                .with_credentials(basic_creds)
                .with_region(IamRegion.value_of(region))
                .build()
            )

            assume_role = IdentityAssumerole(
                agency_name=agency_name,
                duration_seconds=3600,
            )
            if assume_domain_id:
                assume_role.domain_id = assume_domain_id
            else:
                assume_role.domain_name = assume_domain_name

            body = CreateTemporaryAccessKeyByAgencyRequestBody(
                auth=AgencyAuth(
                    identity=AgencyAuthIdentity(
                        methods=["assume_role"],
                        assume_role=assume_role,
                    )
                )
            )

            response = iam_client.create_temporary_access_key_by_agency(
                CreateTemporaryAccessKeyByAgencyRequest(body=body)
            )
            temp = response.credential

            logger.info(
                f"Assumed Huawei Cloud agency '{agency_name}' in target account "
                f"{assume_domain_id or assume_domain_name}"
            )

            return HuaweiCloudCredentials(
                ak=temp.access,
                sk=temp.secret,
                security_token=temp.securitytoken,
                domain_id=assume_domain_id or credentials.domain_id,
            )

        except HuaweiCloudAssumeRoleError:
            raise
        except Exception as error:
            logger.error(
                f"Could not assume Huawei Cloud agency '{agency_name}': {error}"
            )
            raise HuaweiCloudAssumeRoleError(
                file=pathlib.Path(__file__).name,
                original_exception=error,
            )

    @staticmethod
    def validate_credentials(
        session: HuaweiCloudSession,
        region: str = HUAWEICLOUD_DEFAULT_REGION,
    ) -> HuaweiCloudCallerIdentity:
        """
        Validates the Huawei Cloud credentials using IAM API.

        Args:
            session: The Huawei Cloud session object.
            region: The region to use for validation.

        Returns:
            HuaweiCloudCallerIdentity: An object containing the caller identity information.

        Raises:
            HuaweiCloudAuthenticationError: If credentials are invalid.
            HuaweiCloudIdentityError: If the account identity cannot be resolved.
        """
        try:
            from huaweicloudsdkcore.auth.credentials import BasicCredentials
            from huaweicloudsdkiam.v3 import (
                IamClient,
                KeystoneListAuthDomainsRequest,
                KeystoneListAuthProjectsRequest,
            )
            from huaweicloudsdkiam.v3.region.iam_region import IamRegion

            creds = session.get_credentials()

            basic_creds = BasicCredentials(ak=creds.ak, sk=creds.sk)
            # Resolve projects against the region's own IAM endpoint so Huawei
            # Cloud Europe (.eu) accounts are not rejected by the default .com
            # global endpoint.
            iam_endpoint = _iam_endpoint_for_region(region)
            if iam_endpoint:
                basic_creds.iam_endpoint = iam_endpoint
            if creds.security_token:
                basic_creds.security_token = creds.security_token
            if creds.domain_id:
                basic_creds.domain_id = creds.domain_id

            iam_client = (
                IamClient.new_builder()
                .with_credentials(basic_creds)
                .with_region(IamRegion.value_of(region))
                .build()
            )

            iam_client.keystone_list_auth_projects(KeystoneListAuthProjectsRequest())

            domain_id = creds.domain_id or ""
            user_id = ""
            user_name = ""
            account_id = domain_id
            account_name = ""

            try:
                domain_response = iam_client.keystone_list_auth_domains(
                    KeystoneListAuthDomainsRequest()
                )
                if hasattr(domain_response, "domains") and domain_response.domains:
                    for domain in domain_response.domains:
                        if not domain_id:
                            domain_id = getattr(domain, "id", "")
                        if not account_name:
                            account_name = getattr(domain, "name", "")
            except Exception as domain_error:
                logger.debug(f"Could not list auth domains: {domain_error}")

            try:
                from huaweicloudsdkiam.v3 import ShowUserRequest

                user_response = iam_client.show_user(ShowUserRequest(user_id="self"))
                if hasattr(user_response, "user") and user_response.user:
                    user_id = getattr(user_response.user, "id", "")
                    user_name = getattr(user_response.user, "name", "")
            except Exception as user_error:
                logger.debug(f"Could not get current user info: {user_error}")

            if not account_id:
                account_id = domain_id

            if not account_id:
                raise HuaweiCloudIdentityError(
                    file=pathlib.Path(__file__).name,
                    message="Could not determine the Huawei Cloud account or domain id from IAM",
                )

            logger.debug(
                f"Huawei Cloud IAM validation - Domain ID: {domain_id}, Account ID: {account_id}, User: {user_name}"
            )

            return HuaweiCloudCallerIdentity(
                domain_id=domain_id,
                user_id=user_id,
                user_name=user_name,
                account_id=account_id,
                account_name=account_name,
                type="user",
            )

        except (HuaweiCloudAuthenticationError, HuaweiCloudIdentityError):
            raise
        except Exception as iam_error:
            logger.error(f"Could not validate credentials with IAM: {iam_error}")
            raise HuaweiCloudAuthenticationError(
                file=pathlib.Path(__file__).name,
                original_exception=iam_error,
            )

    @staticmethod
    def get_profile_region() -> str:
        """
        Get the profile region.

        Returns:
            str: The profile region
        """
        return HUAWEICLOUD_DEFAULT_REGION

    @staticmethod
    def set_identity(
        caller_identity: HuaweiCloudCallerIdentity,
        profile: str,
        regions: set,
        profile_region: str,
    ) -> HuaweiCloudIdentityInfo:
        """
        Set the Huawei Cloud provider identity information.

        Args:
            caller_identity: The Huawei Cloud caller identity information.
            profile: The profile name.
            regions: A set of regions to audit.
            profile_region: The profile region.

        Returns:
            HuaweiCloudIdentityInfo: The Huawei Cloud provider identity information.
        """
        logger.info(
            f"Huawei Cloud Caller Identity Account ID: {caller_identity.account_id}"
        )
        logger.info(
            f"Huawei Cloud Caller Identity Domain ID: {caller_identity.domain_id}"
        )

        return HuaweiCloudIdentityInfo(
            account_id=caller_identity.account_id,
            account_name=caller_identity.account_name,
            domain_id=caller_identity.domain_id,
            user_id=caller_identity.user_id,
            user_name=caller_identity.user_name,
            identity_type=caller_identity.type,
            regions=regions,
            profile=profile,
            profile_region=profile_region,
        )

    def get_regions_to_audit(self, regions: list = None) -> list:
        """
        get_regions_to_audit returns the list of regions to audit.

        Args:
            regions: List of Huawei Cloud region IDs to audit.

        Returns:
            list: The list of HuaweiCloudRegion objects to audit.

        Raises:
            HuaweiCloudInvalidRegionError: If none of the requested regions are valid.
        """
        from prowler.providers.huaweicloud.models import HuaweiCloudRegion

        region_list = []

        if regions:
            for region_id in regions:
                if region_id in HUAWEICLOUD_REGIONS:
                    region_list.append(
                        HuaweiCloudRegion(
                            region_id=region_id,
                            region_name=HUAWEICLOUD_REGIONS.get(region_id, region_id),
                        )
                    )
                else:
                    logger.warning(f"Invalid region: {region_id}. Skipping.")
            if not region_list:
                raise HuaweiCloudInvalidRegionError(
                    file=pathlib.Path(__file__).name,
                    message=f"None of the requested regions are valid: {regions}",
                )
        else:
            for region_id, region_name in HUAWEICLOUD_REGIONS.items():
                region_list.append(
                    HuaweiCloudRegion(
                        region_id=region_id,
                        region_name=region_name,
                    )
                )

        logger.info(f"Found {len(region_list)} regions to audit")

        if hasattr(self, "_identity") and self._identity:
            self._identity.regions = set([r.region_id for r in region_list])

        return region_list

    def setup_audit_config(self, input_config: dict) -> dict:
        """
        Set up the audit configuration.

        Args:
            input_config: Input configuration dictionary

        Returns:
            Audit configuration dictionary
        """
        audit_config = {
            "shodan_api_key": None,
            **input_config,
        }
        return audit_config

    def print_credentials(self):
        """
        Print the Huawei Cloud credentials.
        """
        regions_str = (
            ", ".join([r.region_id for r in self._regions])
            if self._regions
            else "default regions"
        )

        report_lines = [
            f"Huawei Cloud Account: {Fore.YELLOW}{self.identity.account_id}{Style.RESET_ALL}",
            f"Domain ID: {Fore.YELLOW}{self.identity.domain_id}{Style.RESET_ALL}",
            f"User Name: {Fore.YELLOW}{self.identity.user_name}{Style.RESET_ALL}",
            f"Regions: {Fore.YELLOW}{regions_str}{Style.RESET_ALL}",
        ]

        report_title = (
            f"{Style.BRIGHT}Using the Huawei Cloud credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        access_key_id: str = None,
        secret_access_key: str = None,
        domain_id: str = None,
        security_token: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """
        Test the connection to Huawei Cloud with the provided credentials.

        Args:
            access_key_id: Huawei Cloud Access Key ID
            secret_access_key: Huawei Cloud Secret Access Key
            domain_id: Huawei Cloud Domain ID
            security_token: Security Token (for temporary credentials)
            raise_on_exception: Whether to raise an exception if an error occurs
            provider_id: The expected account ID to validate against

        Returns:
            Connection: An object that contains the result of the test connection operation.
        """
        try:
            session = HuaweicloudProvider.setup_session(
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                domain_id=domain_id,
                security_token=security_token,
            )

            caller_identity = HuaweicloudProvider.validate_credentials(
                session=session,
                region=HUAWEICLOUD_DEFAULT_REGION,
            )

            if provider_id and caller_identity.account_id != provider_id:
                raise HuaweiCloudInvalidProviderIdError(
                    file=pathlib.Path(__file__).name,
                    message=f"Provider ID mismatch: expected '{provider_id}', got '{caller_identity.account_id}'",
                )

            logger.info(
                f"Successfully connected to Huawei Cloud account: {caller_identity.account_id}"
            )

            return Connection(is_connected=True)

        except HuaweiCloudSetUpSessionError as setup_error:
            logger.error(
                f"{setup_error.__class__.__name__}[{setup_error.__traceback__.tb_lineno}]: {setup_error}"
            )
            if raise_on_exception:
                raise setup_error
            return Connection(error=setup_error)

        except HuaweiCloudAuthenticationError as auth_error:
            logger.error(
                f"{auth_error.__class__.__name__}[{auth_error.__traceback__.tb_lineno}]: {auth_error}"
            )
            if raise_on_exception:
                raise auth_error
            return Connection(error=auth_error)

        except HuaweiCloudInvalidProviderIdError as provider_id_error:
            logger.error(
                f"{provider_id_error.__class__.__name__}[{provider_id_error.__traceback__.tb_lineno}]: {provider_id_error}"
            )
            if raise_on_exception:
                raise provider_id_error
            return Connection(error=provider_id_error)

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)

    def generate_regional_clients(self, service: str) -> dict:
        """
        generate_regional_clients returns a dict with regional clients for the given service.

        Args:
            service: The service name (e.g., 'ecs', 'vpc', 'obs').

        Returns:
            dict: A dictionary with region keys and Huawei Cloud service client values.
        """
        try:
            regional_clients = {}

            for region in self._regions:
                try:
                    client = self._session.client(service, region.region_id)
                    if client:
                        client.region = region.region_id
                        regional_clients[region.region_id] = client
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

            return regional_clients

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def get_default_region(self, service: str) -> str:
        """
        Get the default region for a service.

        Returns the first enabled region whose client the service can actually
        build. Not every region is offered by every service (for example, some
        regions have no OBS or KMS endpoint), so the alphabetically-first region
        may be unusable for a given service; probing avoids picking it.

        Args:
            service: The service name

        Returns:
            The default region ID
        """
        candidates = (
            sorted(self.enabled_regions)
            if self.enabled_regions
            else [HUAWEICLOUD_DEFAULT_REGION]
        )
        for region in candidates:
            try:
                self._session.client(service, region)
                return region
            except Exception:
                continue
        return candidates[0]

    def get_checks_to_execute_by_audit_resources(self):
        """
        Get the checks to execute based on audit resources.

        Returns:
            Set of check names to execute
        """
        return set()

    @staticmethod
    def get_regions() -> dict:
        """
        Get the available Huawei Cloud regions.

        Returns:
            dict: A dictionary of region IDs and region names.
        """
        return HUAWEICLOUD_REGIONS
