import sys
from argparse import Namespace
from importlib import import_module
from typing import Optional, Sequence

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider, providers_path

provider_arguments_lib_path = "lib.arguments.arguments"
validate_provider_arguments_function = "validate_arguments"
init_provider_arguments_function = "init_parser"

# Kept in sync with parser.py's argv normalisation; both consumers import this.
PROVIDER_ALIASES = {
    "microsoft365": "m365",
    "oci": "oraclecloud",
}


def _invoked_provider_from_argv(available_providers: Sequence[str]) -> Optional[str]:
    """Return the provider name the user invoked, or None.

    Mirrors `ProwlerArgumentParser.parse()` resolution: only inspects
    `sys.argv[1]`. Scanning the whole argv would misclassify
    `prowler --output-directory stackit` as `stackit`.
    """
    available = set(available_providers)
    if len(sys.argv) < 2:
        return "aws" if "aws" in available else None
    first = sys.argv[1]
    if first in ("-h", "--help", "-v", "--version"):
        return None
    if first.startswith("-"):
        return "aws" if "aws" in available else None
    normalized = PROVIDER_ALIASES.get(first, first)
    return normalized if normalized in available else None


def init_providers_parser(self):
    """Build the subparser of each available provider.

    Built-in load failures are captured silently on
    `self._builtin_load_failures`; the warn/exit decision is deferred to
    `enforce_invoked_provider_loaded()` because `parse(args=...)` can
    override `sys.argv` after this function ran.
    """
    self._builtin_load_failures = {}
    providers = Provider.get_available_providers()
    for provider in providers:
        if Provider.is_builtin(provider):
            try:
                getattr(
                    import_module(
                        f"{providers_path}.{provider}.{provider_arguments_lib_path}"
                    ),
                    init_provider_arguments_function,
                )(self)
            except Exception as error:
                self._builtin_load_failures[provider] = error
        else:
            cls = Provider._load_ep_provider(provider)
            if cls and hasattr(cls, "init_parser"):
                try:
                    cls.init_parser(self)
                except Exception as error:
                    logger.warning(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )


def enforce_invoked_provider_loaded(self):
    """Apply selective fail-loud over the failures captured at init time.

    Called by `ProwlerArgumentParser.parse()` AFTER argv normalisation so
    the invoked provider matches what argparse will dispatch to — including
    the case where `parse(args=...)` overrode the ambient `sys.argv`.

    Invoked + failed → critical + `sys.exit(1)`. Others → warning.
    """
    failures = getattr(self, "_builtin_load_failures", {})
    if not failures:
        return
    invoked = _invoked_provider_from_argv(Provider.get_available_providers())
    for provider, error in failures.items():
        if provider == invoked:
            continue
        if isinstance(error, ImportError):
            logger.warning(
                f"Skipping built-in provider '{provider}' due to missing "
                f"dependency: {error}. It will be unavailable in this "
                f"invocation, but the CLI continues because you invoked a "
                f"different provider."
            )
        else:
            logger.warning(
                f"Skipping built-in provider '{provider}': "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
    if invoked is None or invoked not in failures:
        return
    error = failures[invoked]
    if isinstance(error, ImportError):
        logger.critical(
            f"Failed to load arguments for built-in provider '{invoked}'. "
            f"Missing dependency: {error}. "
            f"Ensure all required dependencies are installed."
        )
        logger.debug("Full traceback:", exc_info=True)
    else:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    sys.exit(1)


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
