import os
import pathlib
import re

import oci
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
from prowler.providers.oraclecloud.config import (
    OCI_DEFAULT_CONFIG_FILE,
    OCI_DEFAULT_PROFILE,
    OCI_REGIONS,
)
from prowler.providers.oraclecloud.exceptions.exceptions import (
    OCIAuthenticationError,
    OCIConfigFileNotFoundError,
    OCIInstancePrincipalError,
    OCIInvalidConfigError,
    OCIInvalidRegionError,
    OCIInvalidTenancyError,
    OCINoCredentialsError,
    OCIProfileNotFoundError,
    OCISetUpSessionError,
)
from prowler.providers.oraclecloud.lib.mutelist.mutelist import OCIMutelist
from prowler.providers.oraclecloud.models import (
    OCICompartment,
    OCIIdentityInfo,
    OCIRegion,
    OCIRegionalClient,
    OCISession,
)


class OraclecloudProvider(Provider):
    """
    OraclecloudProvider class is the main class for the Oracle Cloud Infrastructure provider.

    This class is responsible for initializing the OCI provider, setting up the OCI session,
    validating the OCI credentials, getting the OCI identity, and managing compartments and regions.

    Attributes:
        _type (str): The provider type.
        _identity (OCIIdentityInfo): The OCI provider identity information.
        _session (OCISession): The OCI provider session.
        _audit_config (dict): The audit configuration.
        _regions (list): The list of regions to audit.
        _compartments (list): The list of compartments to audit.
        _mutelist (OCIMutelist): The OCI provider mutelist.
        audit_metadata (Audit_Metadata): The audit metadata.
    """

    _type: str = "oraclecloud"
    _identity: OCIIdentityInfo
    _session: OCISession
    _audit_config: dict
    _regions: list = []
    _compartments: list = []
    _mutelist: OCIMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        oci_config_file: str = None,
        profile: str = None,
        region: str = None,
        compartment_ids: list = None,
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        use_instance_principal: bool = False,
        user: str = None,
        fingerprint: str = None,
        key_file: str = None,
        key_content: str = None,
        tenancy: str = None,
        pass_phrase: str = None,
    ):
        """
        Initializes the OCI provider.

        Args:
            - oci_config_file: The path to the OCI config file.
            - profile: The name of the OCI CLI profile to use.
            - region: The OCI region to audit.
            - compartment_ids: A list of compartment OCIDs to audit.
            - config_path: The path to the Prowler configuration file.
            - config_content: The content of the configuration file.
            - fixer_config: The fixer configuration.
            - mutelist_path: The path to the mutelist file.
            - mutelist_content: The content of the mutelist file.
            - use_instance_principal: Whether to use instance principal authentication.
            - user: The OCID of the user (for API key authentication).
            - fingerprint: The fingerprint of the API signing key.
            - key_file: Path to the private key file.
            - key_content: Content of the private key (base64 encoded).
            - tenancy: The OCID of the tenancy.
            - pass_phrase: The passphrase for the private key, if encrypted.

        Raises:
            - OCISetUpSessionError: If an error occurs during the setup process.
            - OCIAuthenticationError: If authentication fails.

        Usage:
            - OCI SDK is used, so we follow their credential setup process:
                - Authentication: Make sure you have properly configured your OCI CLI with valid credentials.
                    - oci setup config
                    or
                    - export OCI_CLI_AUTH=instance_principal (for instance principal)
                - To create a new OCI provider object:
                    - oci = OraclecloudProvider()
                    - oci = OraclecloudProvider(profile="profile_name")
                    - oci = OraclecloudProvider(oci_config_file="/path/to/config")
                    - oci = OraclecloudProvider(use_instance_principal=True)
                    - oci = OraclecloudProvider(user="ocid1...", fingerprint="...", key_content="...", tenancy="ocid1...", region="us-ashburn-1")
        """

        logger.info("Initializing OCI provider ...")

        # Setup OCI Session
        logger.info("Setting up OCI session ...")
        self._session = self.setup_session(
            oci_config_file=oci_config_file,
            profile=profile,
            use_instance_principal=use_instance_principal,
            user=user,
            fingerprint=fingerprint,
            key_file=key_file,
            key_content=key_content,
            tenancy=tenancy,
            region=region,
            pass_phrase=pass_phrase,
        )

        logger.info("OCI session configured successfully")

        # Validate credentials and get identity
        logger.info("Validating OCI credentials ...")
        self._identity = self.set_identity(
            session=self._session,
            region=region,
            compartment_ids=compartment_ids,
        )
        logger.info("OCI credentials validated")

        # Get regions
        self._regions = self.get_regions_to_audit(region)

        # Get compartments
        self._compartments = self.get_compartments_to_audit(
            compartment_ids, self._identity.tenancy_id
        )

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist
        if mutelist_content:
            self._mutelist = OCIMutelist(
                mutelist_content=mutelist_content,
                tenancy_id=self._identity.tenancy_id,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = OCIMutelist(
                mutelist_path=mutelist_path,
                tenancy_id=self._identity.tenancy_id,
            )

        Provider.set_global_provider(self)

    @property
    def identity(self):
        return self._identity

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def regions(self):
        return self._regions

    @property
    def compartments(self):
        return self._compartments

    @property
    def mutelist(self) -> OCIMutelist:
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    @staticmethod
    def setup_session(
        oci_config_file: str = None,
        profile: str = None,
        use_instance_principal: bool = False,
        user: str = None,
        fingerprint: str = None,
        key_file: str = None,
        key_content: str = None,
        tenancy: str = None,
        region: str = None,
        pass_phrase: str = None,
    ) -> OCISession:
        """
        setup_session sets up an OCI session using the provided credentials.

        Args:
            - oci_config_file: The path to the OCI config file.
            - profile: The name of the OCI CLI profile to use.
            - use_instance_principal: Whether to use instance principal authentication.
            - user: The OCID of the user (for API key authentication).
            - fingerprint: The fingerprint of the API signing key.
            - key_file: Path to the private key file.
            - key_content: Content of the private key (base64 encoded).
            - tenancy: The OCID of the tenancy.
            - region: The OCI region.
            - pass_phrase: The passphrase for the private key, if encrypted.

        Returns:
            - OCISession: The OCI session.

        Raises:
            - OCISetUpSessionError: If an error occurs during the setup process.
        """
        try:
            logger.debug("Creating OCI session ...")

            config = {}
            signer = None

            # If API key credentials are provided directly, create config from them
            if user and fingerprint and tenancy and region:
                import base64

                logger.info("Using API key credentials from direct parameters")

                # Create config dict from provided credentials
                config = {
                    "user": user,
                    "fingerprint": fingerprint,
                    "tenancy": tenancy,
                    "region": region,
                }

                # Handle private key
                if key_content:
                    # Decode base64 key content
                    try:
                        key_data = base64.b64decode(key_content)
                        decoded_key = key_data.decode("utf-8")
                    except Exception as decode_error:
                        logger.error(f"Failed to decode key_content: {decode_error}")
                        raise OCIInvalidConfigError(
                            file=pathlib.Path(__file__).name,
                            message="Failed to decode key_content. Ensure it is base64 encoded.",
                        )

                    # Use OCI SDK's native key_content support
                    config["key_content"] = decoded_key
                elif key_file:
                    config["key_file"] = os.path.expanduser(key_file)
                else:
                    raise OCINoCredentialsError(
                        file=pathlib.Path(__file__).name,
                        message="Either key_file or key_content must be provided",
                    )

                if pass_phrase:
                    config["pass_phrase"] = pass_phrase

                # Validate the config
                try:
                    oci.config.validate_config(config)
                except oci.exceptions.InvalidConfig as error:
                    raise OCIInvalidConfigError(
                        original_exception=error,
                        file=pathlib.Path(__file__).name,
                    )

                return OCISession(config=config, signer=None, profile=None)

            elif use_instance_principal:
                # Use instance principal authentication
                try:
                    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
                    # Get tenancy from instance principal
                    config = {"tenancy": signer.tenancy_id}
                    logger.info("Using instance principal authentication")
                except Exception as error:
                    logger.critical(
                        f"OCIInstancePrincipalError[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    raise OCIInstancePrincipalError(
                        original_exception=error,
                        file=pathlib.Path(__file__).name,
                    )
            else:
                # Use config file authentication
                if not oci_config_file:
                    oci_config_file = os.path.expanduser(OCI_DEFAULT_CONFIG_FILE)

                if not profile:
                    profile = OCI_DEFAULT_PROFILE

                # Check if config file exists
                if not os.path.isfile(oci_config_file):
                    raise OCIConfigFileNotFoundError(
                        file=pathlib.Path(__file__).name,
                        message=f"OCI config file not found at {oci_config_file}",
                    )

                try:
                    config = oci.config.from_file(oci_config_file, profile)
                    oci.config.validate_config(config)

                    # Check if using security token authentication
                    if (
                        "security_token_file" in config
                        and config["security_token_file"]
                    ):
                        logger.info(
                            f"Using profile '{profile}' with session token authentication"
                        )
                        # Use SecurityTokenSigner for session-based auth
                        token_file_path = os.path.expanduser(
                            config["security_token_file"]
                        )
                        with open(token_file_path, "r") as token_file:
                            token = token_file.read().strip()
                        private_key = oci.signer.load_private_key_from_file(
                            config["key_file"]
                        )
                        signer = oci.auth.signers.SecurityTokenSigner(
                            token=token, private_key=private_key
                        )
                    else:
                        logger.info(
                            f"Using profile '{profile}' with API key authentication"
                        )

                except oci.exceptions.InvalidConfig as error:
                    logger.critical(
                        f"OCIInvalidConfigError[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    raise OCIInvalidConfigError(
                        original_exception=error,
                        file=pathlib.Path(__file__).name,
                    )
                except oci.exceptions.ProfileNotFound as error:
                    logger.critical(
                        f"OCIProfileNotFoundError[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    raise OCIProfileNotFoundError(
                        original_exception=error,
                        file=pathlib.Path(__file__).name,
                    )

            return OCISession(
                config=config,
                signer=signer,
                profile=profile if not use_instance_principal else None,
            )

        except Exception as error:
            logger.critical(
                f"OCISetUpSessionError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise OCISetUpSessionError(
                original_exception=error,
                file=pathlib.Path(__file__).name,
            )

    @staticmethod
    def set_identity(
        session: OCISession,
        region: str = None,
        compartment_ids: list = None,
    ) -> OCIIdentityInfo:
        """
        set_identity sets the OCI provider identity information.

        Args:
            - session: The OCI session.
            - region: The OCI region to audit.
            - compartment_ids: A list of compartment OCIDs to audit.

        Returns:
            - OCIIdentityInfo: The OCI provider identity information.

        Raises:
            - OCIAuthenticationError: If authentication fails.
        """
        # Get tenancy from config
        tenancy_id = session.config.get("tenancy")

        if not tenancy_id:
            raise OCINoCredentialsError(
                file=pathlib.Path(__file__).name,
                message="Tenancy ID not found in configuration",
            )

        # Validate tenancy OCID format
        if not OraclecloudProvider.validate_ocid(tenancy_id, "tenancy"):
            raise OCIInvalidTenancyError(
                file=pathlib.Path(__file__).name,
                message=f"Invalid tenancy OCID format: {tenancy_id}",
            )

        # Get user from config (not available in instance principal)
        user_id = session.config.get("user", "instance-principal")

        # Get region from config or use provided region
        if not region:
            region = session.config.get("region", "us-ashburn-1")

        # Validate region
        if region not in OCI_REGIONS:
            raise OCIInvalidRegionError(
                file=pathlib.Path(__file__).name,
                message=f"Invalid region: {region}",
            )

        # Validate credentials by calling OCI Identity service
        try:
            if session.signer:
                identity_client = oci.identity.IdentityClient(
                    config=session.config, signer=session.signer
                )
            else:
                identity_client = oci.identity.IdentityClient(config=session.config)

            tenancy = identity_client.get_tenancy(tenancy_id).data
            tenancy_name = tenancy.name
            logger.info(f"Tenancy Name: {tenancy_name}")
        except oci.exceptions.ServiceError as error:
            logger.critical(
                f"OCI credential validation failed (HTTP {error.status}): {error.message}"
            )
            raise OCIAuthenticationError(
                file=pathlib.Path(__file__).name,
                message=f"OCI credential validation failed: {error.message}. Please verify your credentials and try again.",
                original_exception=error,
            )
        except oci.exceptions.InvalidPrivateKey as error:
            logger.critical(f"Invalid OCI private key: {error}")
            raise OCIAuthenticationError(
                file=pathlib.Path(__file__).name,
                message="Invalid OCI private key format. Ensure the key is a valid PEM-encoded private key.",
                original_exception=error,
            )
        except Exception as error:
            logger.critical(f"OCI authentication error: {error}")
            raise OCIAuthenticationError(
                file=pathlib.Path(__file__).name,
                message=f"Failed to authenticate with OCI: {error}",
                original_exception=error,
            )

        logger.info(f"OCI Tenancy ID: {tenancy_id}")
        logger.info(f"OCI User ID: {user_id}")
        logger.info(f"OCI Region: {region}")

        return OCIIdentityInfo(
            tenancy_id=tenancy_id,
            tenancy_name=tenancy_name,
            user_id=user_id,
            region=region,
            profile=session.profile,
            audited_regions=set([region]) if region else set(),
            audited_compartments=compartment_ids if compartment_ids else [],
        )

    @staticmethod
    def validate_ocid(ocid: str, resource_type: str = None) -> bool:
        """
        validate_ocid validates an OCI OCID format.

        Args:
            - ocid: The OCID to validate.
            - resource_type: The expected resource type (optional).

        Returns:
            - bool: True if valid, False otherwise.
        """
        # OCID pattern: ocid1.<resource_type>.<realm>.<region>.<unique_id>
        ocid_pattern = (
            r"^ocid1\.([a-z0-9_-]+)\.([a-z0-9_-]+)\.([a-z0-9_-]*)\.([a-z0-9]+)$"
        )
        match = re.match(ocid_pattern, ocid)

        if not match:
            return False

        if resource_type:
            return match.group(1) == resource_type

        return True

    def get_regions_to_audit(self, region: str = None) -> list:
        """
        get_regions_to_audit returns the list of regions to audit.

        Args:
            - region: The OCI region to audit.

        Returns:
            - list: The list of OCIRegion objects to audit.
        """
        regions = []

        if region:
            # Audit specific region
            if region in OCI_REGIONS:
                regions.append(
                    OCIRegion(
                        key=region,
                        name=OCI_REGIONS[region],
                        is_home_region=True,
                    )
                )
            else:
                logger.warning(f"Invalid region: {region}. Using default region.")
        else:
            # Audit all subscribed regions
            try:
                # Create identity client with proper authentication handling
                if self._session.signer:
                    identity_client = oci.identity.IdentityClient(
                        config=self._session.config, signer=self._session.signer
                    )
                else:
                    identity_client = oci.identity.IdentityClient(
                        config=self._session.config
                    )
                region_subscriptions = identity_client.list_region_subscriptions(
                    self._identity.tenancy_id
                ).data

                for region_sub in region_subscriptions:
                    regions.append(
                        OCIRegion(
                            key=region_sub.region_name,
                            name=OCI_REGIONS.get(
                                region_sub.region_name, region_sub.region_name
                            ),
                            is_home_region=region_sub.is_home_region,
                        )
                    )

                logger.info(f"Found {len(regions)} subscribed regions")

            except Exception as error:
                logger.warning(
                    f"Could not retrieve region subscriptions: {error}. Using configured region."
                )
                # Fallback to configured region
                config_region = self._session.config.get("region", "us-ashburn-1")
                regions.append(
                    OCIRegion(
                        key=config_region,
                        name=OCI_REGIONS.get(config_region, config_region),
                        is_home_region=True,
                    )
                )

        return regions

    def get_compartments_to_audit(
        self, compartment_ids: list = None, tenancy_id: str = None
    ) -> list:
        """
        get_compartments_to_audit returns the list of compartments to audit.

        Args:
            - compartment_ids: A list of compartment OCIDs to audit.
            - tenancy_id: The tenancy OCID.

        Returns:
            - list: The list of OCICompartment objects to audit.
        """
        compartments = []

        try:
            # Create identity client with proper authentication handling
            if self._session.signer:
                identity_client = oci.identity.IdentityClient(
                    config=self._session.config, signer=self._session.signer
                )
            else:
                identity_client = oci.identity.IdentityClient(
                    config=self._session.config
                )

            if compartment_ids:
                # Audit specific compartments
                for compartment_id in compartment_ids:
                    # Validate compartment OCID
                    if not self.validate_ocid(compartment_id, "compartment"):
                        logger.warning(
                            f"Invalid compartment OCID: {compartment_id}. Skipping."
                        )
                        continue

                    try:
                        compartment_data = identity_client.get_compartment(
                            compartment_id
                        ).data
                        compartments.append(
                            OCICompartment(
                                id=compartment_data.id,
                                name=compartment_data.name,
                                lifecycle_state=compartment_data.lifecycle_state,
                                time_created=compartment_data.time_created,
                                description=compartment_data.description,
                                freeform_tags=compartment_data.freeform_tags,
                                defined_tags=compartment_data.defined_tags,
                            )
                        )
                    except Exception as error:
                        logger.warning(
                            f"Could not retrieve compartment {compartment_id}: {error}"
                        )

            else:
                # Audit all compartments in tenancy (including nested)
                def list_all_compartments(parent_compartment_id, compartments_list):
                    try:
                        compartment_list = identity_client.list_compartments(
                            parent_compartment_id,
                            compartment_id_in_subtree=True,
                            lifecycle_state="ACTIVE",
                        ).data

                        for compartment_data in compartment_list:
                            compartments_list.append(
                                OCICompartment(
                                    id=compartment_data.id,
                                    name=compartment_data.name,
                                    lifecycle_state=compartment_data.lifecycle_state,
                                    time_created=compartment_data.time_created,
                                    description=compartment_data.description,
                                    freeform_tags=compartment_data.freeform_tags,
                                    defined_tags=compartment_data.defined_tags,
                                )
                            )
                    except Exception as error:
                        logger.warning(
                            f"Could not list compartments under {parent_compartment_id}: {error}"
                        )

                # Add root compartment (tenancy)
                try:
                    tenancy_data = identity_client.get_tenancy(tenancy_id).data
                    compartments.append(
                        OCICompartment(
                            id=tenancy_data.id,
                            name=tenancy_data.name,
                            lifecycle_state="ACTIVE",
                            time_created=getattr(tenancy_data, "time_created", None),
                            description=getattr(tenancy_data, "description", ""),
                            freeform_tags=getattr(tenancy_data, "freeform_tags", {}),
                            defined_tags=getattr(tenancy_data, "defined_tags", {}),
                        )
                    )
                except Exception as error:
                    logger.warning(f"Could not retrieve tenancy details: {error}")

                # List all compartments recursively
                list_all_compartments(tenancy_id, compartments)

            # If no compartments were found (due to auth errors), add root compartment as fallback
            if not compartments:
                logger.warning(
                    "No compartments could be retrieved. Using root compartment (tenancy) as fallback."
                )
                compartments.append(
                    OCICompartment(
                        id=tenancy_id,
                        name="root",
                        lifecycle_state="ACTIVE",
                        time_created=None,
                        description="Root compartment (tenancy)",
                    )
                )

            logger.info(f"Found {len(compartments)} compartments to audit")

        except Exception as error:
            logger.warning(
                f"Error retrieving compartments: {error}. Auditing root compartment only."
            )
            # Fallback to root compartment
            compartments.append(
                OCICompartment(
                    id=tenancy_id,
                    name="root",
                    lifecycle_state="ACTIVE",
                    time_created=None,
                    description="Root compartment (tenancy)",
                )
            )

        return compartments

    def print_credentials(self):
        """
        Print the OCI credentials.

        This method prints the OCI credentials used by the provider.

        Example output:
        ```
        Using the OCI credentials below:
        OCI Profile: DEFAULT
        OCI Tenancy: ocid1.tenancy.oc1..example
        OCI User: ocid1.user.oc1..example
        OCI Region: us-ashburn-1
        ```
        """
        # Beautify audited regions
        regions = (
            ", ".join([r.key for r in self._regions])
            if self._regions
            else "all subscribed"
        )
        # Beautify profile
        profile = (
            self._identity.profile if self._identity.profile else "instance-principal"
        )

        report_lines = [
            f"OCI Profile: {Fore.YELLOW}{profile}{Style.RESET_ALL}",
            f"OCI Tenancy: {Fore.YELLOW}{self._identity.tenancy_id}{Style.RESET_ALL}",
            f"OCI Tenancy Name: {Fore.YELLOW}{self._identity.tenancy_name}{Style.RESET_ALL}",
            f"OCI User: {Fore.YELLOW}{self._identity.user_id}{Style.RESET_ALL}",
            f"OCI Region: {Fore.YELLOW}{regions}{Style.RESET_ALL}",
            f"Compartments to audit: {Fore.YELLOW}{len(self._compartments)}{Style.RESET_ALL}",
        ]

        report_title = (
            f"{Style.BRIGHT}Using the OCI credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        oci_config_file: str = None,
        profile: str = None,
        region: str = None,
        use_instance_principal: bool = False,
        raise_on_exception: bool = True,
        provider_id: str = None,
        user: str = None,
        fingerprint: str = None,
        key_file: str = None,
        key_content: str = None,
        tenancy: str = None,
        pass_phrase: str = None,
    ) -> Connection:
        """
        Test the connection to OCI with the provided credentials.

        Args:
            oci_config_file (str): The path to the OCI config file.
            profile (str): The OCI profile to use for the session.
            region (str): The OCI region to validate the credentials in.
            use_instance_principal (bool): Whether to use instance principal authentication.
            raise_on_exception (bool): Whether to raise an exception if an error occurs.
            provider_id (str): The expected tenancy OCID to validate against.
            user (str): The OCID of the user (for API key authentication).
            fingerprint (str): The fingerprint of the API signing key.
            key_file (str): Path to the private key file.
            key_content (str): Content of the private key (base64 encoded).
            tenancy (str): The OCID of the tenancy.
            pass_phrase (str): The passphrase for the private key, if encrypted.

        Returns:
            Connection: An object that contains the result of the test connection operation.
                - is_connected (bool): Indicates whether the validation was successful.
                - error (Exception): An exception object if an error occurs during the validation.

        Raises:
            OCISetUpSessionError: If there is an error setting up the session.
            OCIAuthenticationError: If there is an authentication error.
            OCIInvalidTenancyError: If the provider_id doesn't match the authenticated tenancy.
            Exception: If there is an unexpected error.

        Examples:
            >>> OraclecloudProvider.test_connection(profile="DEFAULT", raise_on_exception=False)
            Connection(is_connected=True, Error=None)
            >>> OraclecloudProvider.test_connection(use_instance_principal=True, raise_on_exception=False)
            Connection(is_connected=True, Error=None)
            >>> OraclecloudProvider.test_connection(
                    user="ocid1.user.oc1..aaaaaa...",
                    fingerprint="12:34:56:78:...",
                    key_content="base64_encoded_key",
                    tenancy="ocid1.tenancy.oc1..aaaaaa...",
                    region="us-ashburn-1",
                    provider_id="ocid1.tenancy.oc1..aaaaaa...",
                    raise_on_exception=False
                )
            Connection(is_connected=True, Error=None)
        """
        try:
            session = None

            # If API key credentials are provided directly, create config from them
            if user and fingerprint and tenancy and region:
                import base64

                logger.info("Using API key credentials from direct parameters")

                # Create config dict from provided credentials
                config = {
                    "user": user,
                    "fingerprint": fingerprint,
                    "tenancy": tenancy,
                    "region": region,
                }

                # Handle private key
                if key_content:
                    # Decode base64 key content
                    try:
                        key_data = base64.b64decode(key_content)
                        decoded_key = key_data.decode("utf-8")
                    except Exception as decode_error:
                        logger.error(f"Failed to decode key_content: {decode_error}")
                        raise OCIInvalidConfigError(
                            file=pathlib.Path(__file__).name,
                            message="Failed to decode key_content. Ensure it is base64 encoded.",
                        )

                    # Use OCI SDK's native key_content support
                    config["key_content"] = decoded_key
                elif key_file:
                    config["key_file"] = os.path.expanduser(key_file)
                else:
                    raise OCINoCredentialsError(
                        file=pathlib.Path(__file__).name,
                        message="Either key_file or key_content must be provided",
                    )

                if pass_phrase:
                    config["pass_phrase"] = pass_phrase

                # Validate the config
                try:
                    oci.config.validate_config(config)
                except oci.exceptions.InvalidConfig as error:
                    raise OCIInvalidConfigError(
                        original_exception=error,
                        file=pathlib.Path(__file__).name,
                    )

                session = OCISession(config=config, signer=None, profile=None)
            else:
                # Use traditional config file or instance principal authentication
                session = OraclecloudProvider.setup_session(
                    oci_config_file=oci_config_file,
                    profile=profile,
                    use_instance_principal=use_instance_principal,
                )

            identity = OraclecloudProvider.set_identity(
                session=session,
                region=region,
            )

            # Validate provider_id if provided
            if provider_id and identity.tenancy_id != provider_id:
                raise OCIInvalidTenancyError(
                    file=pathlib.Path(__file__).name,
                    message=f"Provider ID mismatch: expected '{provider_id}', got '{identity.tenancy_id}'",
                )

            logger.info(f"Successfully connected to OCI tenancy: {identity.tenancy_id}")

            return Connection(is_connected=True)

        except OCISetUpSessionError as setup_error:
            logger.error(
                f"{setup_error.__class__.__name__}[{setup_error.__traceback__.tb_lineno}]: {setup_error}"
            )
            if raise_on_exception:
                raise setup_error
            return Connection(error=setup_error)

        except OCIAuthenticationError as auth_error:
            logger.error(
                f"{auth_error.__class__.__name__}[{auth_error.__traceback__.tb_lineno}]: {auth_error}"
            )
            if raise_on_exception:
                raise auth_error
            return Connection(error=auth_error)

        except OCIInvalidTenancyError as tenancy_error:
            logger.error(
                f"{tenancy_error.__class__.__name__}[{tenancy_error.__traceback__.tb_lineno}]: {tenancy_error}"
            )
            if raise_on_exception:
                raise tenancy_error
            return Connection(error=tenancy_error)

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
            - service: The OCI service name (e.g., 'compute', 'object_storage').

        Returns:
            - dict: A dictionary with region keys and OCI service client values.

        Example:
            {"us-ashburn-1": oci_service_client}
        """
        try:
            regional_clients = {}

            # Map service name to OCI SDK client class
            service_client_map = {
                "compute": oci.core.ComputeClient,
                "blockstorage": oci.core.BlockstorageClient,
                "block_storage": oci.core.BlockstorageClient,  # Alias
                "objectstorage": oci.object_storage.ObjectStorageClient,
                "object_storage": oci.object_storage.ObjectStorageClient,  # Alias
                "identity": oci.identity.IdentityClient,
                "network": oci.core.VirtualNetworkClient,
                "database": oci.database.DatabaseClient,
                "kms": oci.key_management.KmsVaultClient,
                "audit": oci.audit.AuditClient,
                "monitoring": oci.monitoring.MonitoringClient,
                "events": oci.events.EventsClient,
                "functions": oci.functions.FunctionsManagementClient,
                "load_balancer": oci.load_balancer.LoadBalancerClient,
                "filestorage": oci.file_storage.FileStorageClient,
                "file_storage": oci.file_storage.FileStorageClient,  # Alias
                "cloudguard": oci.cloud_guard.CloudGuardClient,
                "cloud_guard": oci.cloud_guard.CloudGuardClient,  # Alias
                "logging": oci.logging.LoggingManagementClient,
                "analytics": oci.analytics.AnalyticsClient,
                "integration": oci.integration.IntegrationInstanceClient,
            }

            if service not in service_client_map:
                logger.error(f"Unknown service: {service}")
                return {}

            client_class = service_client_map[service]

            for region in self._regions:
                try:
                    # Update config with region
                    config_with_region = self._session.config.copy()
                    config_with_region["region"] = region.key

                    # Create regional client with proper authentication handling
                    if self._session.signer:
                        client = client_class(
                            config=config_with_region, signer=self._session.signer
                        )
                    else:
                        client = client_class(config=config_with_region)

                    # Wrap in OCIRegionalClient to include region information
                    regional_clients[region.key] = OCIRegionalClient(
                        client=client, region=region.key
                    )

                except Exception as error:
                    logger.error(
                        f"Error creating {service} client for region {region.key}: {error}"
                    )

            return regional_clients

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    @staticmethod
    def get_regions() -> set:
        """
        Get the available OCI regions.

        Returns:
            set: A set of region names.

        Example:
            >>> OraclecloudProvider.get_regions()
            {"us-ashburn-1", "us-phoenix-1", ...}
        """
        return set(OCI_REGIONS.keys())
