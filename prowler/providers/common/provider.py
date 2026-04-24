import importlib
import importlib.metadata
import os
import pkgutil
import sys
from abc import ABC, abstractmethod
from argparse import Namespace
from importlib import import_module
from typing import Any, Optional

from prowler.config.config import (
    EXTERNAL_TOOL_PROVIDERS,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist

providers_path = "prowler.providers"


# TODO: with this we can enforce that all classes ending with "Provider" needs to inherint from the Provider class
# class ProviderMeta:
#     def __init__(cls, name, bases, dct):
#         # Check if the class name ends with 'Provider'
#         if name.endswith("Provider"):
#             # Check if any base class is a subclass of Provider (or is Provider itself)
#             if not any(issubclass(b, Provider) for b in bases if b is not object):
#                 raise TypeError(f"{name} must inherit from Provider")
#         super().__init__(name, bases, dct)
# class Provider(metaclass=ProviderMeta):


# TODO: enforce audit_metadata for all the providers
class Provider(ABC):
    _global: Optional["Provider"] = None
    mutelist: Mutelist
    """
    The Provider class is an abstract base class that defines the interface for all provider classes in the auditing system.

    Attributes:
        type (property): The type of the provider.
        identity (property): The identity of the provider for auditing.
        session (property): The session of the provider for auditing.
        audit_config (property): The audit configuration of the provider.

    Methods:
        print_credentials(): Displays the provider's credentials used for auditing in the command-line interface.
        setup_session(): Sets up the session for the provider.
        validate_arguments(): Validates the arguments for the provider.
        get_checks_to_execute_by_audit_resources(): Returns a set of checks based on the input resources to scan.

    Note:
        This is an abstract base class and should not be instantiated directly. Each provider should implement its own
        version of the Provider class by inheriting from this base class and implementing the required methods and properties.
    """

    @property
    @abstractmethod
    def type(self) -> str:
        """
        type method stores the provider's type.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def identity(self) -> str:
        """
        identity method stores the provider's identity to audit.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @abstractmethod
    def setup_session(self) -> Any:
        """
        setup_session sets up the session for the provider.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def session(self) -> str:
        """
        session method stores the provider's session to audit.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def audit_config(self) -> str:
        """
        audit_config method stores the provider's audit configuration.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    @abstractmethod
    def print_credentials(self) -> None:
        """
        print_credentials is used to display in the CLI the provider's credentials used to audit.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    # TODO: uncomment this once all the providers have implemented the test_connection method
    # @abstractmethod
    def test_connection(self) -> Any:
        """
        test_connection tests the connection to the provider.

        This method needs to be created in each provider.
        """
        raise NotImplementedError()

    # TODO: probably this won't be here since we want to do the arguments validation during the parse()
    def validate_arguments(self) -> None:
        """
        validate_arguments validates the arguments for the provider.

        This method can be overridden in each provider if needed.
        """
        raise NotImplementedError()

    # TODO: review this since it is only used for AWS
    def get_checks_to_execute_by_audit_resources(self) -> set:
        """
        get_checks_to_execute_by_audit_resources returns a set of checks based on the input resources to scan.

        This is a fallback that returns None if the service has not implemented this function.
        """
        return set()

    # --- Dynamic provider contract methods (not @abstractmethod for incremental migration) ---

    _cli_help_text: str = ""

    @classmethod
    def from_cli_args(cls, arguments: Namespace, fixer_config: dict) -> "Provider":
        """Instantiate the provider from CLI arguments."""
        raise NotImplementedError(f"{cls.__name__} has not implemented from_cli_args()")

    def get_output_options(self, arguments, bulk_checks_metadata):
        """Create the provider-specific OutputOptions."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_output_options()"
        )

    def get_stdout_detail(self, finding) -> str:
        """Return the detail string for stdout reporting (region, location, etc.)."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_stdout_detail()"
        )

    def get_finding_sort_key(self) -> Optional[str]:
        """Return the attribute name to sort findings by, or None for no sorting."""
        return None

    def get_summary_entity(self) -> tuple:
        """Return (entity_type, audited_entities) for the summary table."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_summary_entity()"
        )

    def get_finding_output_data(self, check_output) -> dict:
        """Return provider-specific fields for Finding.generate_output()."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_finding_output_data()"
        )

    def get_html_assessment_summary(self) -> str:
        """Return the HTML assessment summary card for this provider."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_html_assessment_summary()"
        )

    def generate_compliance_output(
        self,
        findings,
        bulk_compliance_frameworks,
        input_compliance_frameworks,
        output_options,
        generated_outputs,
    ) -> None:
        """Generate compliance CSV output for this provider's frameworks."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented generate_compliance_output()"
        )

    def get_mutelist_finding_args(self) -> dict:
        """Return extra kwargs for mutelist.is_finding_muted() besides 'finding'.

        External providers must return a dict with the identity key their
        Mutelist subclass expects, e.g. ``{"account_id": self.identity.account_id}``.
        The ``finding`` kwarg is added automatically by the caller.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_mutelist_finding_args()"
        )

    def display_compliance_table(
        self,
        findings: list,
        bulk_checks_metadata: dict,
        compliance_framework: str,
        output_filename: str,
        output_directory: str,
        compliance_overview: bool,
    ) -> bool:
        """Render a custom compliance table in the terminal.

        External providers can override this to display a detailed
        compliance table (e.g., per-section breakdown). Return True
        if the table was rendered, False to fall back to the generic table.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented display_compliance_table()"
        )

    # Class-level flag: True for providers that delegate scanning to an external
    # tool (e.g. Trivy, promptfoo) and bypass standard check/service loading and
    # metadata validation. Subclasses override as `is_external_tool_provider = True`.
    # Kept as a class attribute (not a property) so it can be read from the class
    # without instantiation — the metadata validators in lib.check.models need to
    # decide whether to relax validation before any provider instance exists.
    is_external_tool_provider: bool = False

    # --- End dynamic provider contract methods ---

    @staticmethod
    def get_excluded_regions_from_env() -> set:
        """Parse the PROWLER_AWS_DISALLOWED_REGIONS environment variable.

        The variable is a comma-separated list of region identifiers to skip
        during scans (e.g. "me-south-1, ap-east-1"). Whitespace around entries
        is tolerated and empty entries are dropped. Returns an empty set when
        the variable is unset or contains no usable values.
        """
        raw = os.environ.get("PROWLER_AWS_DISALLOWED_REGIONS", "")
        return {region.strip() for region in raw.split(",") if region.strip()}

    @staticmethod
    def get_global_provider() -> "Provider":
        return Provider._global

    @staticmethod
    def set_global_provider(global_provider: "Provider") -> None:
        Provider._global = global_provider

    @staticmethod
    def init_global_provider(arguments: Namespace) -> None:
        try:
            # Try built-in provider first, fall back to entry point
            provider_class = None
            try:
                provider_class_path = f"{providers_path}.{arguments.provider}.{arguments.provider}_provider"
                provider_class_name = f"{arguments.provider.capitalize()}Provider"
                provider_class = getattr(
                    import_module(provider_class_path), provider_class_name
                )
            except (ImportError, AttributeError):
                # External provider — load via entry point
                provider_class = Provider._load_ep_provider(arguments.provider)
                if provider_class is None:
                    raise ImportError(
                        f"Provider '{arguments.provider}' not found as built-in or entry point"
                    )

            fixer_config = load_and_validate_config_file(
                arguments.provider, arguments.fixer_config
            )

            if not isinstance(Provider._global, provider_class):
                if "aws" in provider_class_name.lower():
                    excluded_regions = (
                        set(arguments.excluded_region)
                        if getattr(arguments, "excluded_region", None)
                        else None
                    )
                    provider_class(
                        retries_max_attempts=arguments.aws_retries_max_attempts,
                        role_arn=arguments.role,
                        session_duration=arguments.session_duration,
                        external_id=arguments.external_id,
                        role_session_name=arguments.role_session_name,
                        mfa=arguments.mfa,
                        profile=arguments.profile,
                        regions=set(arguments.region) if arguments.region else None,
                        excluded_regions=excluded_regions,
                        organizations_role_arn=arguments.organizations_role,
                        scan_unused_services=arguments.scan_unused_services,
                        resource_tags=arguments.resource_tag,
                        resource_arn=arguments.resource_arn,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "azure" in provider_class_name.lower():
                    provider_class(
                        az_cli_auth=arguments.az_cli_auth,
                        sp_env_auth=arguments.sp_env_auth,
                        browser_auth=arguments.browser_auth,
                        managed_identity_auth=arguments.managed_identity_auth,
                        tenant_id=arguments.tenant_id,
                        region=arguments.azure_region,
                        subscription_ids=arguments.subscription_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "gcp" in provider_class_name.lower():
                    provider_class(
                        retries_max_attempts=arguments.gcp_retries_max_attempts,
                        organization_id=arguments.organization_id,
                        project_ids=arguments.project_id,
                        excluded_project_ids=arguments.excluded_project_id,
                        credentials_file=arguments.credentials_file,
                        impersonate_service_account=arguments.impersonate_service_account,
                        list_project_ids=arguments.list_project_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                        skip_api_check=arguments.skip_api_check,
                    )
                elif "kubernetes" in provider_class_name.lower():
                    provider_class(
                        kubeconfig_file=arguments.kubeconfig_file,
                        context=arguments.context,
                        namespace=arguments.namespace,
                        cluster_name=arguments.cluster_name,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "m365" in provider_class_name.lower():
                    provider_class(
                        region=arguments.region,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        sp_env_auth=arguments.sp_env_auth,
                        az_cli_auth=arguments.az_cli_auth,
                        browser_auth=arguments.browser_auth,
                        certificate_auth=arguments.certificate_auth,
                        certificate_path=arguments.certificate_path,
                        tenant_id=arguments.tenant_id,
                        init_modules=arguments.init_modules,
                        fixer_config=fixer_config,
                    )
                elif "nhn" in provider_class_name.lower():
                    provider_class(
                        username=arguments.nhn_username,
                        password=arguments.nhn_password,
                        tenant_id=arguments.nhn_tenant_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "github" in provider_class_name.lower():
                    orgs = []
                    repos = []

                    if getattr(arguments, "organization", None):
                        orgs.extend(arguments.organization)
                    if getattr(arguments, "organizations", None):
                        orgs.extend(arguments.organizations)
                    if getattr(arguments, "repository", None):
                        repos.extend(arguments.repository)
                    if getattr(arguments, "repositories", None):
                        repos.extend(arguments.repositories)

                    orgs = list(dict.fromkeys(orgs))
                    repos = list(dict.fromkeys(repos))

                    provider_class(
                        personal_access_token=arguments.personal_access_token,
                        oauth_app_token=arguments.oauth_app_token,
                        github_app_key=arguments.github_app_key,
                        github_app_id=arguments.github_app_id,
                        mutelist_path=arguments.mutelist_file,
                        config_path=arguments.config_file,
                        repositories=repos,
                        repo_list_file=getattr(arguments, "repo_list_file", None),
                        organizations=orgs,
                    )
                elif "googleworkspace" in provider_class_name.lower():
                    provider_class(
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "cloudflare" in provider_class_name.lower():
                    provider_class(
                        filter_zones=arguments.region,
                        filter_accounts=arguments.account_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "iac" in provider_class_name.lower():
                    provider_class(
                        scan_path=arguments.scan_path,
                        scan_repository_url=arguments.scan_repository_url,
                        scanners=arguments.scanners,
                        exclude_path=arguments.exclude_path,
                        config_path=arguments.config_file,
                        fixer_config=fixer_config,
                        github_username=arguments.github_username,
                        personal_access_token=arguments.personal_access_token,
                        oauth_app_token=arguments.oauth_app_token,
                        provider_uid=arguments.provider_uid,
                    )
                elif "llm" in provider_class_name.lower():
                    provider_class(
                        max_concurrency=arguments.max_concurrency,
                        config_path=arguments.config_file,
                        fixer_config=fixer_config,
                    )
                elif "image" in provider_class_name.lower():
                    provider_class(
                        images=arguments.images,
                        image_list_file=arguments.image_list_file,
                        scanners=arguments.scanners,
                        image_config_scanners=arguments.image_config_scanners,
                        trivy_severity=arguments.trivy_severity,
                        ignore_unfixed=arguments.ignore_unfixed,
                        timeout=arguments.timeout,
                        config_path=arguments.config_file,
                        fixer_config=fixer_config,
                        registry=arguments.registry,
                        image_filter=arguments.image_filter,
                        tag_filter=arguments.tag_filter,
                        max_images=arguments.max_images,
                        registry_insecure=arguments.registry_insecure,
                        registry_list_images=arguments.registry_list_images,
                    )
                elif "mongodbatlas" in provider_class_name.lower():
                    provider_class(
                        atlas_public_key=arguments.atlas_public_key,
                        atlas_private_key=arguments.atlas_private_key,
                        atlas_project_id=arguments.atlas_project_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "oraclecloud" in provider_class_name.lower():
                    provider_class(
                        oci_config_file=arguments.oci_config_file,
                        profile=arguments.profile,
                        region=set(arguments.region) if arguments.region else None,
                        compartment_ids=arguments.compartment_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                        use_instance_principal=arguments.use_instance_principal,
                    )
                elif "openstack" in provider_class_name.lower():
                    provider_class(
                        clouds_yaml_file=getattr(arguments, "clouds_yaml_file", None),
                        clouds_yaml_content=getattr(
                            arguments, "clouds_yaml_content", None
                        ),
                        clouds_yaml_cloud=getattr(arguments, "clouds_yaml_cloud", None),
                        auth_url=getattr(arguments, "os_auth_url", None),
                        identity_api_version=getattr(
                            arguments, "os_identity_api_version", None
                        ),
                        username=getattr(arguments, "os_username", None),
                        password=getattr(arguments, "os_password", None),
                        project_id=getattr(arguments, "os_project_id", None),
                        region_name=getattr(arguments, "os_region_name", None),
                        user_domain_name=getattr(
                            arguments, "os_user_domain_name", None
                        ),
                        project_domain_name=getattr(
                            arguments, "os_project_domain_name", None
                        ),
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "alibabacloud" in provider_class_name.lower():
                    provider_class(
                        role_arn=arguments.role_arn,
                        role_session_name=arguments.role_session_name,
                        ecs_ram_role=arguments.ecs_ram_role,
                        oidc_role_arn=arguments.oidc_role_arn,
                        credentials_uri=arguments.credentials_uri,
                        regions=arguments.regions,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif "vercel" in provider_class_name.lower():
                    provider_class(
                        projects=getattr(arguments, "project", None),
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                else:
                    # Dynamic fallback: any external/custom provider
                    provider_class.from_cli_args(arguments, fixer_config)

        except TypeError as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    # Cache for entry-point provider classes {name: class}
    _ep_providers: dict = {}

    @staticmethod
    def get_available_providers() -> list[str]:
        """get_available_providers returns a list of the available providers"""
        providers = set()
        # Built-in providers from local package
        prowler_providers = importlib.import_module(providers_path)
        for _, provider, ispkg in pkgutil.iter_modules(prowler_providers.__path__):
            if provider != "common" and ispkg:
                providers.add(provider)
        # External providers registered via entry points
        for ep in importlib.metadata.entry_points(group="prowler.providers"):
            providers.add(ep.name)
        return sorted(providers)

    @staticmethod
    def is_tool_wrapper_provider(provider: str) -> bool:
        """Return True if the provider delegates scanning to an external tool.

        Combines the built-in EXTERNAL_TOOL_PROVIDERS frozenset (fast path for
        iac/llm/image) with the `is_external_tool_provider` class attribute of
        external plug-in providers registered via entry points. This is the
        single source of truth consulted by the execution flow and the
        CheckMetadata validators.
        """
        if provider in EXTERNAL_TOOL_PROVIDERS:
            return True
        ep_cls = Provider._load_ep_provider(provider)
        return bool(ep_cls and getattr(ep_cls, "is_external_tool_provider", False))

    @staticmethod
    def _load_ep_provider(name: str):
        """Load an external provider class from entry points, with cache."""
        if name in Provider._ep_providers:
            return Provider._ep_providers[name]
        for ep in importlib.metadata.entry_points(group="prowler.providers"):
            if ep.name == name:
                try:
                    cls = ep.load()
                    Provider._ep_providers[name] = cls
                    return cls
                except Exception as error:
                    logger.warning(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        return None

    @staticmethod
    def get_providers_help_text() -> dict:
        """Returns a dict of {provider_name: cli_help_text} for all available providers."""
        help_text = {}
        for name in Provider.get_available_providers():
            try:
                # Try built-in first
                module_path = f"{providers_path}.{name}.{name}_provider"
                module = import_module(module_path)
                cls = None
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, Provider)
                        and attr is not Provider
                    ):
                        cls = attr
                        break
                help_text[name] = getattr(cls, "_cli_help_text", "") if cls else ""
            except ImportError:
                # External provider — load via entry point
                cls = Provider._load_ep_provider(name)
                help_text[name] = getattr(cls, "_cli_help_text", "") if cls else ""
            except Exception as error:
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                help_text[name] = ""
        return help_text

    @staticmethod
    def update_provider_config(audit_config: dict, variable: str, value: str):
        try:
            if audit_config and variable in audit_config:
                audit_config[variable] = value

            return audit_config
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
