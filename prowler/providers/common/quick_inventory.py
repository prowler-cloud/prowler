import importlib
import sys

from prowler.lib.logger import logger
from prowler.providers.aws.lib.quick_inventory.quick_inventory import quick_inventory


def run_provider_quick_inventory(provider, audit_info, output_directory):
    """
    run_provider_quick_inventory executes the quick inventory for te provider
    """
    try:
        # Dynamically get the Provider quick inventory handler
        provider_quick_inventory_function = f"{provider}_quick_inventory"
        getattr(importlib.import_module(__name__), provider_quick_inventory_function)(
            audit_info, output_directory
        )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)


def aws_quick_inventory(audit_info, output_directory):
    quick_inventory(audit_info, output_directory)
