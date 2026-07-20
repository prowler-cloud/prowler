import importlib
import importlib.metadata
import importlib.util
import os
import pkgutil
import sys
from abc import ABC, abstractmethod
from argparse import Namespace
from importlib import import_module
from typing import Any, Optional

from prowler.config.config import load_and_validate_config_file
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

    # CLI/SDK-only provider, hidden from the app (API/UI). Defaults True; a
    # provider opts into the app with ``sdk_only = False``. See get_app_providers().
    sdk_only: bool = True

    @classmethod
    def from_cli_args(cls, arguments: Namespace, fixer_config: dict) -> "Provider":
        """Instantiate the provider from CLI arguments and return the instance.

        The caller wires the returned instance into the global provider slot
        via Provider.set_global_provider(). Implementations that already call
        set_global_provider(self) from __init__ are also supported — the call
        site tolerates a None return in that case.
        """
        raise NotImplementedError(f"{cls.__name__} has not implemented from_cli_args()")

    def get_output_options(self, arguments, _bulk_checks_metadata):
        """Create the provider-specific OutputOptions."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_output_options()"
        )

    def get_stdout_detail(self, _finding) -> str:
        """Return the detail string for stdout reporting (region, location, etc.)."""
        raise NotImplementedError(
            f"{self.__class__.__name__} has not implemented get_stdout_detail()"
        )

    def get_finding_sort_key(self) -> Optional[str]:
        """Return the attribute name to sort findings by, or None for no sorting."""
        return None

    def get_summary_entity(self) -> tuple:
        """Return (entity_type, audited_entities) for the summary table."""
        return (self.type, getattr(self.identity, "account_id", ""))

    def get_finding_output_data(self, _check_output) -> dict:
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
        _findings,
        _bulk_compliance_frameworks,
        _input_compliance_frameworks,
        _output_options,
        _generated_outputs,
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

    @classmethod
    def get_scan_arguments(
        cls,
        provider_uid: str,
        secret: dict,
        mutelist_content: Optional[dict] = None,
    ) -> dict:
        """Build the provider constructor kwargs from a stored uid and secret.

        This is the programmatic construction interface intended for callers
        that will persist a provider as a single ``uid`` plus a ``secret`` dict
        (e.g. the API), as opposed to the CLI which passes explicit per-provider
        flags.

        The base implementation is a default: it passes the secret through, adds
        the mutelist, and intentionally drops ``provider_uid``. The API consumes
        this contract for external providers, so an external provider whose uid
        is part of the scan scope (e.g. a subscription or project id) or that
        renames/filters secret keys overrides this to inject the uid into the
        right kwarg; until it does, the base default is not the final shape for
        that provider. Built-in providers whose scope derives from the uid are
        mapped on the API side and do not go through this method.
        """
        kwargs = {**secret}
        if mutelist_content is not None:
            kwargs["mutelist_content"] = mutelist_content
        return kwargs

    @classmethod
    def get_connection_arguments(cls, provider_uid: str, secret: dict) -> dict:
        """Build the ``test_connection`` kwargs from a stored uid and secret.

        Companion to :meth:`get_scan_arguments` for the connection check, which
        often needs a different shape than the constructor. The base passes the
        secret through and intentionally drops ``provider_uid``. An external
        provider whose uid is part of the scope overrides this to add its
        identity kwarg (and ``provider_id`` where its ``test_connection``
        expects it); built-in providers are mapped on the API side and do not go
        through this method.
        """
        return {**secret}

    @classmethod
    def get_credentials_schema(cls) -> dict:
        """Return the provider's credential schemas keyed by secret type.

        Maps each secret type the provider accepts (``"static"``, ``"role"`` or
        ``"service_account"``) to the pydantic model that validates a secret of
        that type. The provider declares which type each schema belongs to, so
        the API validates a secret against the model for the secret type it is
        created with and the chosen type stays bound to the shape it claims.

        Each model documents each field via ``Field(description=...)`` and
        whether it is required (no default) or optional. An empty dict means no
        schema is declared: the secret is accepted as an object and validated by
        :meth:`test_connection`.
        """
        return {}

    def display_compliance_table(
        self,
        _findings: list,
        _bulk_checks_metadata: dict,
        _compliance_framework: str,
        _output_filename: str,
        _output_directory: str,
        _compliance_overview: bool,
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
            # Delegate class resolution to the public, side-effect-free
            # resolver.  init_global_provider owns the CLI-specific error
            # handling: a missing transitive dep in a built-in becomes a
            # logger.critical + sys.exit(1); a completely unknown provider
            # re-raises so the outer try/except can sys.exit too.
            try:
                provider_class = Provider.get_class(arguments.provider)
            except ImportError as e:
                if Provider.is_builtin(arguments.provider):
                    # Built-in's transitive dependency is missing — loud CLI error.
                    logger.critical(
                        f"Failed to load built-in provider '{arguments.provider}'. "
                        f"Missing dependency: {e}. "
                        f"Ensure all required dependencies are installed."
                    )
                    logger.debug("Full traceback:", exc_info=True)
                    sys.exit(1)
                # Unknown or missing external provider — propagate so the
                # outer try/except can handle it (sys.exit(1) via generic
                # exception handler).
                raise

            # Built-in wins on name collision — warn that a same-named
            # plug-in is ignored.  This lives here (not in get_class) so
            # that `prowler --help` and API callers that resolve a class
            # without initialising a global provider do not see spurious
            # warnings. Match by name only — never ep.load() a shadowing
            # plug-in, or its module code would run during a built-in run.
            if Provider.is_builtin(arguments.provider) and any(
                ep.name == arguments.provider
                for ep in importlib.metadata.entry_points(group="prowler.providers")
            ):
                logger.warning(
                    f"Plug-in provider '{arguments.provider}' registered "
                    f"via entry points is being IGNORED — a built-in with "
                    f"the same name exists. To use your plug-in, register "
                    f"it under a different name."
                )

            fixer_config = load_and_validate_config_file(
                arguments.provider, arguments.fixer_config
            )

            # Dispatch by exact provider name (equality, not substring) so
            # external plug-ins whose names contain a built-in substring
            # (e.g. `awsx`, `azure_gov`, `iac_v2`) cannot be silently routed
            # to the wrong built-in branch. Anything that doesn't match a
            # built-in falls through to the dynamic else and uses the
            # contract's `from_cli_args`.
            if not isinstance(Provider._global, provider_class):
                if arguments.provider == "aws":
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
                elif arguments.provider == "azure":
                    provider_class(
                        az_cli_auth=arguments.az_cli_auth,
                        sp_env_auth=arguments.sp_env_auth,
                        browser_auth=arguments.browser_auth,
                        managed_identity_auth=arguments.managed_identity_auth,
                        tenant_id=arguments.tenant_id,
                        region=arguments.azure_region,
                        subscription_ids=arguments.subscription_id,
                        resource_groups=arguments.resource_groups,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "gcp":
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
                elif arguments.provider == "kubernetes":
                    provider_class(
                        kubeconfig_file=arguments.kubeconfig_file,
                        context=arguments.context,
                        namespace=arguments.namespace,
                        cluster_name=arguments.cluster_name,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "m365":
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
                elif arguments.provider == "nhn":
                    provider_class(
                        username=arguments.nhn_username,
                        password=arguments.nhn_password,
                        tenant_id=arguments.nhn_tenant_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "stackit":
                    provider_class(
                        project_id=arguments.stackit_project_id,
                        service_account_key_path=getattr(
                            arguments, "stackit_service_account_key_path", None
                        ),
                        service_account_key=getattr(
                            arguments, "stackit_service_account_key", None
                        ),
                        regions=(
                            set(arguments.stackit_region)
                            if arguments.stackit_region
                            else None
                        ),
                        scan_unused_services=arguments.scan_unused_services,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "github":
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
                        github_actions_enabled=not getattr(
                            arguments, "no_github_actions", False
                        ),
                        exclude_workflows=getattr(arguments, "exclude_workflows", []),
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "googleworkspace":
                    provider_class(
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "cloudflare":
                    provider_class(
                        filter_zones=arguments.region,
                        filter_accounts=arguments.account_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "iac":
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
                elif arguments.provider == "llm":
                    provider_class(
                        max_concurrency=arguments.max_concurrency,
                        config_path=arguments.config_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "image":
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
                elif arguments.provider == "mongodbatlas":
                    provider_class(
                        atlas_public_key=arguments.atlas_public_key,
                        atlas_private_key=arguments.atlas_private_key,
                        atlas_project_id=arguments.atlas_project_id,
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "oraclecloud":
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
                elif arguments.provider == "openstack":
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
                elif arguments.provider == "alibabacloud":
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
                elif arguments.provider == "vercel":
                    provider_class(
                        projects=getattr(arguments, "project", None),
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "e2enetworks":
                    provider_class(
                        api_key=getattr(arguments, "e2e_networks_api_key", None),
                        auth_token=getattr(arguments, "e2e_networks_auth_token", None),
                        project_id=getattr(arguments, "e2e_networks_project_id", None),
                        locations=getattr(arguments, "region", None),
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "okta":
                    provider_class(
                        okta_org_domain=getattr(arguments, "okta_org_domain", ""),
                        okta_client_id=getattr(arguments, "okta_client_id", ""),
                        okta_private_key=getattr(arguments, "okta_private_key", ""),
                        okta_private_key_file=getattr(
                            arguments, "okta_private_key_file", ""
                        ),
                        okta_scopes=getattr(arguments, "okta_scopes", None),
                        okta_retries_max_attempts=getattr(
                            arguments, "okta_retries_max_attempts", None
                        ),
                        okta_requests_per_second=getattr(
                            arguments, "okta_requests_per_second", None
                        ),
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "scaleway":
                    # Credentials are read from the SCW_ACCESS_KEY /
                    # SCW_SECRET_KEY env vars by the provider itself; there
                    # are no credential CLI flags to avoid leaking secrets.
                    provider_class(
                        organization_id=getattr(arguments, "organization_id", None),
                        project_id=getattr(arguments, "project_id", None),
                        region=getattr(arguments, "region", None),
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                    )
                elif arguments.provider == "linode":
                    # Credentials are read from the LINODE_TOKEN env var by the
                    # provider itself; there are no credential CLI flags to
                    # avoid leaking secrets.
                    provider_class(
                        config_path=arguments.config_file,
                        mutelist_path=arguments.mutelist_file,
                        fixer_config=fixer_config,
                        regions=getattr(arguments, "region", None),
                    )
                else:
                    # Dynamic fallback: any external/custom provider.
                    # Honor the from_cli_args type hint (-> Provider): if the
                    # implementation returns an instance, wire it as the global
                    # provider here. Implementations that call
                    # set_global_provider(self) from __init__ return None and
                    # remain supported (the condition below is a no-op for them).
                    provider_instance = provider_class.from_cli_args(
                        arguments, fixer_config
                    )
                    if provider_instance is not None:
                        Provider.set_global_provider(provider_instance)

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
    def get_app_providers() -> list[str]:
        """Return the providers the app (API/UI) may expose: those with
        ``sdk_only = False``.

        Counterpart of :meth:`get_available_providers`, which lists every
        provider for the CLI. A provider whose class cannot be imported is
        treated as ``sdk_only`` (excluded) so a broken plug-in never leaks in.
        """
        app_providers = []
        for name in Provider.get_available_providers():
            try:
                provider_class = Provider.get_class(name)
            except Exception as error:
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                continue
            if not getattr(provider_class, "sdk_only", True):
                app_providers.append(name)
        return app_providers

    @staticmethod
    def is_tool_wrapper_provider(provider: str) -> bool:
        """Return True if the provider delegates scanning to an external tool.

        Delegates to `prowler.lib.check.tool_wrapper.is_tool_wrapper_provider`,
        the leaf module that holds the actual logic. Kept on `Provider` as a
        convenience entry point for callers that already import `Provider`.
        """
        from prowler.lib.check.tool_wrapper import is_tool_wrapper_provider as _impl

        return _impl(provider)

    @staticmethod
    def is_builtin(provider: str) -> bool:
        """Return True if the provider's own package is importable as a built-in.

        Delegates to `prowler.providers.common.builtin.is_builtin_provider`,
        the leaf module that holds the actual check. Kept on `Provider` as a
        convenience entry point for callers that already import `Provider`.
        Call sites in `prowler.lib.check.*` should import from the leaf
        directly to avoid the import cycle through this module.
        """
        from prowler.providers.common.builtin import is_builtin_provider as _impl

        return _impl(provider)

    @staticmethod
    def _load_ep_provider(name: str):
        """Load an external provider class from entry points, with cache.

        Caches both hits and misses so repeated lookups for unknown names do
        not re-iterate entry_points(). Symmetric with
        tool_wrapper._ep_class_cache.
        """
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
        Provider._ep_providers[name] = None
        return None

    @staticmethod
    def get_class(provider: str) -> type:
        """Resolve the provider class for a name (built-in or entry-point).

        Does not call ``sys.exit`` and does not initialize the global
        provider (it may populate the ``_ep_providers`` memoization cache).
        Collision warnings are emitted by ``init_global_provider``, not here.
        The caller handles errors (CLI exits; the API can return HTTP 400).

        Args:
            provider: Provider name, e.g. ``"aws"`` or an external plug-in.

        Returns:
            The provider class (a subclass of :class:`Provider`).

        Raises:
            ImportError: If not found as built-in or entry point, a built-in's
                transitive dependency is missing, or an entry point resolves to
                an object that is not a subclass of :class:`Provider`.
        """
        if Provider.is_builtin(provider):
            provider_class_path = f"{providers_path}.{provider}.{provider}_provider"
            provider_class_name = f"{provider.capitalize()}Provider"
            # Let ImportError propagate — the caller decides whether to
            # sys.exit (CLI) or return HTTP 400 (API).
            module = import_module(provider_class_path)
            try:
                return getattr(module, provider_class_name)
            except AttributeError as error:
                # is_builtin already confirmed this is a built-in, so the
                # module MUST define the expected class. A missing class is a
                # broken built-in contract — raise rather than fall back to a
                # same-named external plug-in, which would contradict
                # is_builtin and silently return a foreign class.
                raise ImportError(
                    f"Built-in provider '{provider}' module "
                    f"'{provider_class_path}' does not define expected class "
                    f"'{provider_class_name}'"
                ) from error

        cls = Provider._load_ep_provider(provider)
        if cls is None:
            raise ImportError(
                f"Provider '{provider}' not found as built-in or entry point"
            )
        # ep.load() can return any object; enforce the public contract that
        # get_class returns a Provider subclass. isinstance(cls, type) guards
        # issubclass against a TypeError when cls is not a class at all.
        if not (isinstance(cls, type) and issubclass(cls, Provider)):
            raise ImportError(
                f"Entry-point provider '{provider}' resolved to {cls!r}, "
                f"which is not a subclass of Provider"
            )
        return cls

    @staticmethod
    def get_providers_help_text() -> dict:
        """Returns a dict of {provider_name: cli_help_text} for all available providers."""
        help_text = {}
        for name in Provider.get_available_providers():
            try:
                cls = Provider.get_class(name)
                help_text[name] = getattr(cls, "_cli_help_text", "")
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
