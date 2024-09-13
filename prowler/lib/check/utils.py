import importlib
import sys
from pkgutil import walk_packages

from prowler.lib.logger import logger


def recover_checks_from_provider(
    provider: str, service: str = None, include_fixers: bool = False
) -> list[tuple]:
    """
    Recover all checks from the selected provider and service

    Returns a list of tuples with the following format (check_name, check_path)
    """
    try:
        checks = []
        modules = list_modules(provider, service)
        for module_name in modules:
            # Format: "prowler.providers.{provider}.services.{service}.{check_name}.{check_name}"
            check_module_name = module_name.name
            # We need to exclude common shared libraries in services
            if (
                check_module_name.count(".") == 6
                and "lib" not in check_module_name
                and (not check_module_name.endswith("_fixer") or include_fixers)
            ):
                check_path = module_name.module_finder.path
                # Check name is the last part of the check_module_name
                check_name = check_module_name.split(".")[-1]
                check_info = (check_name, check_path)
                checks.append(check_info)
    except ModuleNotFoundError:
        logger.critical(f"Service {service} was not found for the {provider} provider.")
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
