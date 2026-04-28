import importlib
import importlib.metadata
import os
import sys
from pkgutil import walk_packages

from prowler.lib.logger import logger


def _recover_ep_checks(provider: str, service: str = None) -> list[tuple]:
    """Discover external checks registered via entry points for a provider.

    External plugins follow the same layout as built-ins:
    `{plugin_root}.services.{service}.{check}.{check}`

    When `service` is provided, only entry points whose dotted path contains
    `.services.{service}.` are included — mirroring how built-in discovery
    filters by the `prowler.providers.{provider}.services.{service}` package.

    Uses find_spec to locate the check module without importing it,
    avoiding service client initialization at discovery time.
    """
    checks = []
    for ep in importlib.metadata.entry_points(group=f"prowler.checks.{provider}"):
        try:
            if service and f".services.{service}." not in ep.value:
                continue

            spec = importlib.util.find_spec(ep.value)
            if spec and spec.origin:
                check_path = os.path.dirname(spec.origin)
                checks.append((ep.name, check_path))
        except Exception as error:
            logger.warning(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
    return checks


def recover_checks_from_provider(
    provider: str, service: str = None, include_fixers: bool = False
) -> list[tuple]:
    """
    Recover all checks from the selected provider and service

    Returns a list of tuples with the following format (check_name, check_path)
    """
    try:
        # Bypass check loading for tool-wrapper providers — they delegate
        # scanning to an external tool and have no checks to recover.
        # Single source of truth: combines the EXTERNAL_TOOL_PROVIDERS
        # frozenset (built-ins) with the per-provider `is_external_tool_provider`
        # class attribute (so external plug-ins opt in via the contract).
        from prowler.providers.common.provider import Provider

        if Provider.is_tool_wrapper_provider(provider):
            return []

        checks = []
        # Built-in checks from prowler.providers.{provider}.services
        try:
            modules = list_modules(provider, service)
            for module_name in modules:
                # Format: "prowler.providers.{provider}.services.{service}.{check_name}.{check_name}"
                check_module_name = module_name.name
                # We need to exclude common shared libraries in services
                if (
                    check_module_name.count(".") == 6
                    and ".lib." not in check_module_name
                    and (not check_module_name.endswith("_fixer") or include_fixers)
                ):
                    check_path = module_name.module_finder.path
                    check_name = check_module_name.split(".")[-1]
                    check_info = (check_name, check_path)
                    checks.append(check_info)
        except ModuleNotFoundError:
            # Not a built-in provider (or the requested service is not built-in).
            # Fall through to entry points — external providers/services may be
            # registered there. If nothing matches in either source, we fail
            # with a clear message below.
            pass

        # External checks registered via entry points — always consulted, with
        # optional service filter. Previously gated by `if not service:`, which
        # prevented external providers from being usable with --service.
        checks.extend(_recover_ep_checks(provider, service))

        # A service was requested but nothing matched in either built-ins or
        # entry points — surface this as a clear error instead of silently
        # returning an empty list.
        if service and not checks:
            logger.critical(
                f"Service '{service}' was not found for the '{provider}' provider "
                f"(neither as a built-in nor via external entry points)."
            )
            sys.exit(1)

    except Exception as e:
        logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}")
        sys.exit(1)
    else:
        return checks


# List all available modules in the selected provider and service
def list_modules(provider: str, service: str):
    # This module path requires the full path including "prowler."
    module_path = f"prowler.providers.{provider}.services"
    if service:
        module_path += f".{service}"
    return walk_packages(
        importlib.import_module(module_path).__path__,
        importlib.import_module(module_path).__name__ + ".",
    )


def recover_checks_from_service(service_list: list, provider: str) -> set:
    """
    Recover all checks from the selected provider and service

    Returns a set of checks from the given services
    """
    try:
        # Bypass check loading for tool-wrapper providers — symmetric with
        # `recover_checks_from_provider` above, using the same source of truth.
        # NOTE: master gated this on `provider in EXTERNAL_TOOL_PROVIDERS`
        # (covering iac/llm/image). The PR temporarily narrowed it to `== "iac"`;
        # restoring the full set via the helper.
        from prowler.providers.common.provider import Provider

        if Provider.is_tool_wrapper_provider(provider):
            return set()

        checks = set()
        service_list = [
            "awslambda" if service == "lambda" else service for service in service_list
        ]
        for service in service_list:
            service_checks = recover_checks_from_provider(provider, service)
            if not service_checks:
                logger.error(f"Service '{service}' does not have checks.")

            else:
                for check in service_checks:
                    # Recover check name and module name from import path
                    # Format: "providers.{provider}.services.{service}.{check_name}.{check_name}"
                    check_name = check[0].split(".")[-1]
                    # If the service is present in the group list passed as parameters
                    # if service_name in group_list: checks_from_arn.add(check_name)
                    checks.add(check_name)
        return checks
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def list_compliance_modules():
    """
    list_compliance_modules returns the available compliance frameworks and returns their path
    """
    # This module path requires the full path including "prowler."
    module_path = "prowler.compliance"
    return walk_packages(
        importlib.import_module(module_path).__path__,
        importlib.import_module(module_path).__name__ + ".",
    )
