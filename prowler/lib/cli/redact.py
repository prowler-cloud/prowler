from functools import lru_cache
from importlib import import_module

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider, providers_path

REDACTED_VALUE = "REDACTED"


@lru_cache(maxsize=None)
def get_sensitive_arguments() -> frozenset:
    """Collect SENSITIVE_ARGUMENTS from all provider argument modules and the common parser."""
    sensitive: set[str] = set()

    # Common parser sensitive arguments (e.g., --shodan)
    try:
        parser_module = import_module("prowler.lib.cli.parser")
        sensitive.update(getattr(parser_module, "SENSITIVE_ARGUMENTS", frozenset()))
    except Exception as error:
        logger.debug(f"Could not load SENSITIVE_ARGUMENTS from parser: {error}")

    # Provider-specific sensitive arguments
    for provider in Provider.get_available_providers():
        try:
            module = import_module(
                f"{providers_path}.{provider}.lib.arguments.arguments"
            )
            sensitive.update(getattr(module, "SENSITIVE_ARGUMENTS", frozenset()))
        except Exception as error:
            logger.debug(f"Could not load SENSITIVE_ARGUMENTS from {provider}: {error}")

    return frozenset(sensitive)


def redact_argv(argv: list[str]) -> str:
    """Redact values of sensitive CLI flags from an argument list.

    Handles both ``--flag value`` and ``--flag=value`` syntax.
    Returns a single joined string suitable for display.
    """
    sensitive = get_sensitive_arguments()
    result: list[str] = []
    skip_next = False

    for i, arg in enumerate(argv):
        if skip_next:
            result.append(REDACTED_VALUE)
            skip_next = False
            continue

        # Handle --flag=value syntax
        if "=" in arg:
            flag = arg.split("=", 1)[0]
            if flag in sensitive:
                result.append(f"{flag}={REDACTED_VALUE}")
                continue

        # Handle --flag value syntax
        if arg in sensitive:
            result.append(arg)
            # Only redact the next token if it exists and is not another flag
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                skip_next = True
            continue

        result.append(arg)

    return " ".join(result)
