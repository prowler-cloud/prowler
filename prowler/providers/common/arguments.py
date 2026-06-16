import sys
from argparse import Namespace
from importlib import import_module
from typing import Optional, Sequence

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider, providers_path

provider_arguments_lib_path = "lib.arguments.arguments"
validate_provider_arguments_function = "validate_arguments"
init_provider_arguments_function = "init_parser"

# User-facing provider names that map to a different canonical built-in name.
# Single source of truth: parser.py imports this so the alias is recognised
# both when sniffing argv pre-parse and when rewriting argv pre-argparse.
PROVIDER_ALIASES = {
    "microsoft365": "m365",
    "oci": "oraclecloud",
}


def _invoked_provider_from_argv(available_providers: Sequence[str]) -> Optional[str]:
    """Return the provider name the user invoked on the CLI, or None.

    Scans sys.argv left-to-right, skipping flag-like tokens, and returns the
    first non-flag token that matches a known provider name (after alias
    normalisation). Returns None if no provider is being invoked (e.g.
    `prowler -h`, `prowler dashboard`, or empty argv).

    Assumes the top-level parser has no flags that consume a value (only
    --version/-v as of today). If that ever changes, the invariant test
    `test_top_level_parser_has_no_value_consuming_flags` in
    tests/lib/cli/parser_test.py fails and this function must be updated to
    also skip the flag's value when scanning for the invoked provider.
    """
    available = set(available_providers)
    for token in sys.argv[1:]:
        if token.startswith("-"):
            continue
        normalized = PROVIDER_ALIASES.get(token, token)
        if normalized in available:
            return normalized
    return None


def init_providers_parser(self):
    """init_providers_parser calls the provider init_parser function to load all the arguments and flags. Receives a ProwlerArgumentParser object"""
    # We need to call the arguments parser for each provider
    providers = Provider.get_available_providers()
    # A built-in provider with a broken optional dependency should not tear
    # down the whole CLI when the user invoked a different, sane provider.
    # Only fail-loud on the invoked provider; otherwise warn and continue so
    # the rest of the parser still builds.
    invoked = _invoked_provider_from_argv(providers)
    for provider in providers:
        is_invoked = provider == invoked
        # Discriminate built-in vs external upfront via find_spec, so an
        # ImportError from a transitive dependency missing inside a built-in
        # arguments module surfaces clearly instead of being silently
        # re-routed to the entry-point path (which only has external providers).
        if Provider.is_builtin(provider):
            try:
                getattr(
                    import_module(
                        f"{providers_path}.{provider}.{provider_arguments_lib_path}"
                    ),
                    init_provider_arguments_function,
                )(self)
            except ImportError as e:
                if is_invoked:
                    logger.critical(
                        f"Failed to load arguments for built-in provider '{provider}'. "
                        f"Missing dependency: {e}. "
                        f"Ensure all required dependencies are installed."
                    )
                    logger.debug("Full traceback:", exc_info=True)
                    sys.exit(1)
                logger.warning(
                    f"Skipping built-in provider '{provider}' due to missing "
                    f"dependency: {e}. It will be unavailable in this invocation, "
                    f"but the CLI continues because you invoked a different provider."
                )
            except Exception as error:
                if is_invoked:
                    logger.critical(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    sys.exit(1)
                logger.warning(
                    f"Skipping built-in provider '{provider}': "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        else:
            # External provider — init_parser classmethod via entry point
            cls = Provider._load_ep_provider(provider)
            if cls and hasattr(cls, "init_parser"):
                try:
                    cls.init_parser(self)
                except Exception as error:
                    logger.warning(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )


def validate_provider_arguments(arguments: Namespace) -> tuple[bool, str]:
    """validate_provider_arguments returns {True, "} if the provider arguments passed are valid and can be used together"""
    try:
        # Provider function must be located at prowler.providers.<provider>.lib.arguments.arguments.validate_arguments
        return getattr(
            import_module(
                f"{providers_path}.{arguments.provider}.{provider_arguments_lib_path}"
            ),
            validate_provider_arguments_function,
        )(arguments)

    # If the provider does not have a lib.arguments package we return (True, "")
    except ModuleNotFoundError:
        return (True, "")

    # If the provider does not have a validate_arguments we return (True, "")
    except AttributeError:
        return (True, "")

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)


def validate_asff_usage(
    provider: Optional[str], output_formats: Optional[Sequence[str]]
) -> tuple[bool, str]:
    """Ensure json-asff output is only requested for the AWS provider."""
    if not output_formats or "json-asff" not in output_formats:
        return (True, "")

    if provider == "aws":
        return (True, "")

    return (
        False,
        f"json-asff output format is only available for the aws provider, but {provider} was selected",
    )


def validate_sarif_usage(
    provider: Optional[str], output_formats: Optional[Sequence[str]]
) -> tuple[bool, str]:
    """Ensure sarif output is only requested for the IaC provider."""
    if not output_formats or "sarif" not in output_formats:
        return (True, "")

    if provider == "iac":
        return (True, "")

    return (
        False,
        f"sarif output format is only available for the iac provider, but {provider} was selected",
    )
