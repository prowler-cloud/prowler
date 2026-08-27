"""File templates used by the provider scaffold command.

Placeholders use ``string.Template`` syntax (``$name``) rather than
``str.format`` because the rendered output is Python source containing literal
braces (dicts, f-strings, annotations) that ``str.format`` would try to
interpret.

Two constraints shape these templates:

- Generated code lands in a contributor's working tree, where Prowler's own CI
  runs ``black --check`` and ``flake8`` over it. Rendered output must therefore
  already be formatter-clean and free of unused imports, which is why the
  optional blocks below carry their own trailing newlines instead of relying on
  the substitution site to get the blank lines right.
- Every template stops where a provider-specific decision starts.
  Authentication behavior, API semantics and security checks are marked
  ``TODO`` rather than guessed.
"""

from string import Template

PROVIDER_CLASS = Template('''import os

from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
$provider_imports


class ${class_prefix}Provider(Provider):
    """$class_prefix provider."""

    _type: str = "$name"
    _session: ${class_prefix}Session
    _identity: ${class_prefix}IdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: ${class_prefix}Mutelist
    _cli_help_text: str = "$class_prefix Provider"
$sdk_only_attr    audit_metadata: Audit_Metadata

    def __init__(
        self,
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
$init_extra_params    ):
        """Initialize the ${class_prefix}Provider instance.

        Args:
            config_path: Path to the audit configuration file.
            config_content: Audit configuration content, used instead of config_path.
            fixer_config: Fixer configuration.
            mutelist_path: Path to the mutelist file.
            mutelist_content: Mutelist content, used instead of mutelist_path.
$init_extra_docs
        Raises:
            ${class_prefix}CredentialsError: If no usable credentials are found.
            ${class_prefix}SessionError: If the session cannot be established.
            ${class_prefix}IdentityError: If the identity cannot be retrieved.
        """
        logger.info("Instantiating $class_prefix provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = ${class_prefix}Provider.setup_session($session_call_args)
$regions_init
        self._identity = ${class_prefix}Provider.setup_identity(self._session)

        self._fixer_config = fixer_config if fixer_config is not None else {}

        if mutelist_content:
            self._mutelist = ${class_prefix}Mutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = ${class_prefix}Mutelist(mutelist_path=mutelist_path)

        Provider.set_global_provider(self)

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> ${class_prefix}Mutelist:
        return self._mutelist
$regions_property
    @staticmethod
    def setup_session($session_def_params) -> ${class_prefix}Session:
        """Build the authenticated $class_prefix session.

        $auth_docstring

        Returns:
            ${class_prefix}Session: The initialized session.

        Raises:
            ${class_prefix}CredentialsError: If no usable credentials are found.
            ${class_prefix}SessionError: If the client cannot be built.
        """
        # TODO: resolve credentials and build the client for this provider.
        # $auth_hint
        raise ${class_prefix}CredentialsError(
            file=os.path.basename(__file__),
            message="TODO: implement ${class_prefix}Provider.setup_session().",
        )

    @staticmethod
    def setup_identity(session: ${class_prefix}Session) -> ${class_prefix}IdentityInfo:
        """Read the identity of the audited $class_prefix target.

        The fields returned here appear in Prowler's output, so they are this
        provider's identity contract.

        Args:
            session: The $class_prefix session.

        Returns:
            ${class_prefix}IdentityInfo: The identity information.

        Raises:
            ${class_prefix}IdentityError: If the identity cannot be retrieved.
        """
        # TODO: call the API that identifies the audited target and map the
        # response onto ${class_prefix}IdentityInfo.
        raise ${class_prefix}IdentityError(
            file=os.path.basename(__file__),
            message="TODO: implement ${class_prefix}Provider.setup_identity().",
        )
$validate_regions
    def print_credentials(self) -> None:
        """Print the credentials Prowler is auditing with."""
        report_title = (
            f"{Style.BRIGHT}Using the $class_prefix credentials below:{Style.RESET_ALL}"
        )
        report_lines = [
            f"Authentication: {Fore.YELLOW}$auth_label{Style.RESET_ALL}",
        ]
        # TODO: append the identity fields worth showing before a scan starts.
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
$test_connection_params        raise_on_exception: bool = True,
    ) -> Connection:
        """Check whether Prowler can reach $class_prefix with these credentials.

        Args:
$test_connection_docs            raise_on_exception: Whether to raise instead of returning a failed Connection.

        Returns:
            Connection: The connection result.
        """
        try:
            ${class_prefix}Provider.setup_session($session_call_args)
            # TODO: make one cheap read-only call here to prove the credentials
            # work before returning a successful Connection.
            return Connection(is_connected=True)
        except ${class_prefix}CredentialsError as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise
            return Connection(is_connected=False, error=error)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise ${class_prefix}SessionError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                )
            return Connection(is_connected=False, error=error)
''')

REGIONS_INIT = Template("""
        # Region filter for regional resources. None means scan every region.
        self._regions = ${class_prefix}Provider.validate_regions(self._session, regions)
""")

REGIONS_PROPERTY = Template('''
    @property
    def regions(self):
        """Regions to scan for regional resources, or None for all of them."""
        return self._regions
''')

VALIDATE_REGIONS = Template('''
    @staticmethod
    def validate_regions(session: ${class_prefix}Session, regions: list = None):
        """Validate the requested regions against the ones $class_prefix offers.

        Args:
            session: The $class_prefix session.
            regions: The region ids requested with --region, or None.

        Returns:
            The validated set of region ids, or None when no filter is given.
        """
        if not regions:
            return None
        # TODO: validate the requested ids against the live region list and
        # raise a provider exception naming the invalid ones.
        return set(regions)
''')

MODELS = Template('''from typing import Any, Optional

from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class ${class_prefix}Session(BaseModel):
    """$class_prefix session information."""

    # TODO: replace `client` with the concrete client type once the SDK or
    # HTTP client for this provider is chosen.
    client: Any = None


class ${class_prefix}IdentityInfo(BaseModel):
    """$class_prefix identity and scoping information.

    These fields identify the audited target and appear in Prowler's output,
    so they are this provider's identity contract.
    """

    # TODO: replace this with the fields that actually identify an audited
    # $class_prefix target (account, organization, project, tenant, user).
    account_id: Optional[str] = None


class ${class_prefix}OutputOptions(ProviderOutputOptions):
    """Customize output filenames for $class_prefix scans."""

    def __init__(
        self, arguments, bulk_checks_metadata, identity: ${class_prefix}IdentityInfo
    ):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = identity.account_id or "$name"
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
''')

ARGUMENTS = Template('''${sensitive_arguments}def init_parser(self):
    """Init the $class_prefix provider CLI parser."""
    ${parser_assignment}self.subparsers.add_parser(
        "$name",
        parents=[self.common_providers_parser],
        help="$class_prefix Provider",
    )
$auth_arguments$regions_arguments''')

SENSITIVE_ARGUMENTS = Template(
    """# Values passed to these flags are redacted in HTML output and trigger a
# warning telling users to prefer the environment variable instead.
SENSITIVE_ARGUMENTS = frozenset({"--$name-token"})


"""
)

ARGUMENTS_AUTH_ENV = Template("""
    # Authentication
    # Credentials are read from the ${env_prefix}_* environment variables so
    # that secrets never reach shell history or process listings. There are
    # deliberately no credential CLI flags.
    # TODO: name the environment variables this provider reads.
""")

ARGUMENTS_AUTH_TOKEN = Template("""
    # Authentication
    auth_subparser = ${name}_parser.add_argument_group(
        "Authentication Modes",
    )
    auth_subparser.add_argument(
        "--$name-token",
        nargs="?",
        default=None,
        metavar="${env_prefix}_TOKEN",
        help="$class_prefix API token. Use the ${env_prefix}_TOKEN environment "
        "variable instead of passing the value directly.",
    )
""")

ARGUMENTS_AUTH_KEY_FILE = Template("""
    # Authentication
    auth_subparser = ${name}_parser.add_argument_group(
        "Authentication Modes",
    )
    auth_subparser.add_argument(
        "--$name-key-file",
        nargs="?",
        default=None,
        metavar="${env_prefix}_KEY_FILE",
        help="Path to the $class_prefix credentials key file. Defaults to the "
        "${env_prefix}_KEY_FILE environment variable.",
    )
""")

ARGUMENTS_AUTH_BROWSER = Template("""
    # Authentication
    auth_subparser = ${name}_parser.add_argument_group(
        "Authentication Modes",
    )
    auth_subparser.add_argument(
        "--$name-browser-auth",
        action="store_true",
        default=False,
        help="Authenticate against $class_prefix with the interactive browser flow.",
    )
""")

ARGUMENTS_REGIONS = Template("""
    # Regions
    regions_subparser = ${name}_parser.add_argument_group(
        "Regions",
    )
    regions_subparser.add_argument(
        "--region",
        "--filter-region",
        "-f",
        nargs="+",
        default=None,
        metavar="REGION",
        help="$class_prefix region(s) to scan. Region-less resources are always "
        "scanned. If omitted, every region is scanned.",
    )
""")

EXCEPTIONS = Template('''from prowler.exceptions.exceptions import ProwlerException


# Exception codes from $code_start to $code_end are reserved for $class_prefix exceptions
class ${class_prefix}BaseException(ProwlerException):
    """Base class for $class_prefix errors."""

    ${env_prefix}_ERROR_CODES = {
        ($code_credentials, "${class_prefix}CredentialsError"): {
            "message": "$class_prefix credentials not found or invalid",
            "remediation": "TODO: name the environment variables or flags that supply valid credentials.",
        },
        ($code_session, "${class_prefix}SessionError"): {
            "message": "$class_prefix session setup failed",
            "remediation": "TODO: name what to check when the client cannot be built.",
        },
        ($code_identity, "${class_prefix}IdentityError"): {
            "message": "Unable to retrieve $class_prefix identity information",
            "remediation": "TODO: name the permission or scope the identity call needs.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "$class_prefix"
        error_info = self.${env_prefix}_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown $class_prefix error",
                "remediation": "Check the $class_prefix API documentation for more details.",
            }
        elif message:
            error_info = error_info.copy()
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class ${class_prefix}CredentialsError(${class_prefix}BaseException):
    """Exception for $class_prefix credential errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            $code_credentials,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class ${class_prefix}SessionError(${class_prefix}BaseException):
    """Exception for $class_prefix session setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            $code_session,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class ${class_prefix}IdentityError(${class_prefix}BaseException):
    """Exception for $class_prefix identity errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            $code_identity,
            file=file,
            original_exception=original_exception,
            message=message,
        )
''')

MUTELIST = Template('''from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class ${class_prefix}Mutelist(Mutelist):
    """$class_prefix-specific mutelist helper."""

    def is_finding_muted(self, finding, account_id: str) -> bool:
        """Check whether a $class_prefix finding is muted.

        Args:
            finding: The check report for this provider. TODO: annotate this as
                CheckReport$class_prefix once that class is added to
                prowler/lib/check/models.py.
            account_id: The $class_prefix account identifier.

        Returns:
            True if the finding is muted, False otherwise.
        """
        return self.is_muted(
            account_id,
            finding.check_metadata.CheckID,
            finding.region or "global",
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
''')

SERVICE_BASE = Template('''from prowler.lib.logger import logger
from prowler.providers.$name.${name}_provider import ${class_prefix}Provider


class ${class_prefix}Service:
    """Base class for $class_prefix services, sharing the provider context."""

    def __init__(self, service: str, provider: ${class_prefix}Provider):
        """Initialize the service with the provider context.

        Args:
            service: The $class_prefix service name.
            provider: The ${class_prefix}Provider instance.
        """
        self.provider = provider
        self.client = provider.session.client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service

    def _log_fetch_error(self, resource_label: str, error: Exception) -> None:
        """Log a failed resource fetch without aborting the rest of the scan.

        A single service losing access must not end the whole scan, so this
        logs and returns instead of raising.

        Args:
            resource_label: The resources that could not be fetched.
            error: The exception raised by the API call.
        """
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: "
            f"Unable to fetch $name {resource_label} -- {error}"
        )
''')

SERVICES_INIT = Template("""# Each service lives in its own package next to this file:
#
#     services/<service>/<service>_service.py   resource fetcher
#     services/<service>/<service>_client.py    module-level singleton
#     services/<service>/<check>/<check>.py     one check per package
#     services/<service>/<check>/<check>.metadata.json
#
# The scaffold stops here because a service name and its API calls are
# provider-specific. See the prowler-sdk-check skill for the next step.
""")

PROVIDER_TEST = Template('''from unittest.mock import patch

import pytest
from tests.providers.$name.${name}_fixtures import set_mocked_${name}_provider

$provider_imports


class Test${class_prefix}Provider:
    def test_provider_type(self):
        """The provider reports the name the CLI dispatches on."""
        assert ${class_prefix}Provider._type == "$name"

    def test_provider_class_name_matches_discovery(self):
        """Provider.get_class() builds the class name with str.capitalize().

        A multi-word name spelled with inner capitals breaks discovery, so this
        assertion is what keeps the provider loadable.
        """
        assert ${class_prefix}Provider.__name__ == "$name".capitalize() + "Provider"

    def test_provider_application_exposure(self):
        """sdk_only decides whether the API and UI list this provider."""
        assert ${class_prefix}Provider.sdk_only is $sdk_only_value

    def test_setup_session_is_not_implemented_yet(self):
        """TODO: replace this with a test of the real session setup."""
        with pytest.raises(${class_prefix}CredentialsError):
            ${class_prefix}Provider.setup_session($session_test_args)

    def test_setup_identity_is_not_implemented_yet(self):
        """TODO: replace this with a test of the real identity mapping."""
        with pytest.raises(${class_prefix}IdentityError):
            ${class_prefix}Provider.setup_identity(None)

    def test_print_credentials(self):
        """print_credentials runs against a provider that makes no calls."""
        provider = set_mocked_${name}_provider()
        with patch(
            "prowler.providers.$name.${name}_provider.print_boxes"
        ) as mocked_print_boxes:
            provider.print_credentials()
        assert mocked_print_boxes.called
''')

PROVIDER_FIXTURES = Template('''from unittest.mock import MagicMock

$provider_imports

# TODO: replace this with a value that resembles a real audited target.
${env_prefix}_ACCOUNT_ID = "$name-account-id"


def set_mocked_${name}_provider(
    audit_config: dict = None,
    fixer_config: dict = None,
) -> ${class_prefix}Provider:
    """Build a ${class_prefix}Provider that performs no network calls.

    Args:
        audit_config: Audit configuration to expose on the provider.
        fixer_config: Fixer configuration to expose on the provider.

    Returns:
        A MagicMock specced against ${class_prefix}Provider.
    """
    provider = MagicMock(spec=${class_prefix}Provider)
    provider.type = "$name"
    provider.session = ${class_prefix}Session(client=MagicMock())
    provider.identity = ${class_prefix}IdentityInfo(account_id=${env_prefix}_ACCOUNT_ID)
    provider.audit_config = audit_config if audit_config is not None else {}
    provider.fixer_config = fixer_config if fixer_config is not None else {}
    provider.print_credentials = lambda: ${class_prefix}Provider.print_credentials(
        provider
    )
    return provider
''')

ARGUMENTS_TEST = Template(
    '''from prowler.providers.$name.lib.arguments.arguments import init_parser


class Test${class_prefix}Arguments:
    def test_init_parser_is_callable(self):
        """init_providers_parser() imports this module for every built-in.

        prowler/providers/common/arguments.py calls init_parser on it, so a
        missing or renamed function makes the provider unusable from the CLI.
        """
        assert callable(init_parser)
'''
)

EXTERNAL_PYPROJECT = Template("""[build-system]
build-backend = "hatchling.build"
requires = ["hatchling"]

[project]
name = "prowler-provider-$name"
version = "0.1.0"
description = "$class_prefix provider for Prowler"
requires-python = ">=3.10"
dependencies = ["prowler"]

# Prowler discovers external providers through this entry point group. The name
# on the left is what `prowler <name>` dispatches on, and the value must resolve
# to a Provider subclass or Prowler rejects it.
[project.entry-points."prowler.providers"]
$name = "prowler_provider_${name}.provider:${class_prefix}Provider"

[tool.hatch.build.targets.wheel]
packages = ["prowler_provider_$name"]
""")

EXTERNAL_PROVIDER = Template(
    '''"""$class_prefix provider, distributed as an external Prowler plug-in."""

from argparse import Namespace

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider

from prowler_provider_${name}.models import (
    ${class_prefix}IdentityInfo,
    ${class_prefix}Session,
)


class ${class_prefix}Provider(Provider):
    """$class_prefix provider.

    An external provider cannot join the `elif` chain in
    `init_global_provider()`, so it owns two pieces of the contract that no
    built-in provider implements:

    - `init_parser`, which `prowler/providers/common/arguments.py` calls to
      build this provider's CLI subparser.
    - `from_cli_args`, which the dynamic fallback branch of
      `init_global_provider()` calls to build the instance.
    """

    _type: str = "$name"
    _cli_help_text: str = "$class_prefix Provider"
$sdk_only_attr
    def __init__(
        self,
        config_path: str = None,
        fixer_config: dict = None,
$init_extra_params    ):
        logger.info("Instantiating $class_prefix provider...")
        self._audit_config = {}
        self._fixer_config = fixer_config if fixer_config is not None else {}
        self._session = ${class_prefix}Provider.setup_session($session_call_args)
        self._identity = ${class_prefix}IdentityInfo()
        Provider.set_global_provider(self)

    def init_parser(self):
        """Build this provider's CLI subparser.

        Called as `cls.init_parser(parser)`, so `self` here is Prowler's
        argument parser rather than a provider instance. That mirrors the
        module-level `init_parser(self)` that built-in providers define.
        """
        ${parser_assignment}self.subparsers.add_parser(
            "$name",
            parents=[self.common_providers_parser],
            help="$class_prefix Provider",
        )
$auth_arguments$regions_arguments
    @classmethod
    def from_cli_args(cls, arguments: Namespace, fixer_config: dict) -> "Provider":
        """Build the provider from the parsed CLI arguments.

        Args:
            arguments: The parsed CLI namespace.
            fixer_config: The loaded fixer configuration.

        Returns:
            The provider instance.
        """
        return cls(
            config_path=getattr(arguments, "config_file", None),
            fixer_config=fixer_config,
$from_cli_args_extra        )

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @staticmethod
    def setup_session($session_def_params) -> ${class_prefix}Session:
        """Build the authenticated $class_prefix session.

        $auth_docstring
        """
        # TODO: resolve credentials and build the client for this provider.
        # $auth_hint
        raise NotImplementedError(
            "TODO: implement ${class_prefix}Provider.setup_session()."
        )

    def print_credentials(self) -> None:
        """Print the credentials Prowler is auditing with."""
        logger.info("Scanning $class_prefix with $auth_label")
'''
)

EXTERNAL_MODELS = Template('''from typing import Any, Optional

from pydantic import BaseModel


class ${class_prefix}Session(BaseModel):
    """$class_prefix session information."""

    # TODO: replace `client` with the concrete client type.
    client: Any = None


class ${class_prefix}IdentityInfo(BaseModel):
    """$class_prefix identity and scoping information."""

    # TODO: replace this with the fields that identify an audited target.
    account_id: Optional[str] = None
''')

EXTERNAL_README = Template("""# prowler-provider-$name

External [Prowler](https://github.com/prowler-cloud/prowler) provider for
$class_prefix, discovered at runtime through the `prowler.providers` entry
point. It installs alongside Prowler instead of living in the Prowler
repository.

## Install

```bash
pip install prowler
pip install -e .
```

## Verify Discovery

```bash
prowler --help          # $name appears in the provider list
prowler $name --help    # $name shows its own arguments
```

A name that clashes with a built-in provider is ignored in favour of the
built-in, so pick a name no built-in already uses.

## What Is Left To Do

Search this package for `TODO`. The scaffold generates structure only, so
authentication, the identity mapping and the security checks are yours.
""")

EXTERNAL_TEST = Template('''from prowler.providers.common.provider import Provider

from prowler_provider_${name}.provider import ${class_prefix}Provider


class Test${class_prefix}Provider:
    def test_provider_subclasses_provider(self):
        """Prowler rejects an entry point that is not a Provider subclass."""
        assert issubclass(${class_prefix}Provider, Provider)

    def test_provider_declares_the_external_contract(self):
        """An external provider needs both halves of the CLI contract."""
        assert hasattr(${class_prefix}Provider, "init_parser")
        assert hasattr(${class_prefix}Provider, "from_cli_args")

    def test_provider_type(self):
        assert ${class_prefix}Provider._type == "$name"
''')
