import importlib
import sys

from prowler.lib.logger import logger
from prowler.providers.aws.lib.quick_inventory.quick_inventory import quick_inventory


def run_provider_quick_inventory(provider, args):
    """
    run_provider_quick_inventory executes the quick inventory for the provider
    """
    try:
        # Dynamically get the Provider quick inventory handler
        provider_quick_inventory_function = f"{provider.type}_quick_inventory"
        getattr(importlib.import_module(__name__), provider_quick_inventory_function)(
            provider, args
        )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)


def aws_quick_inventory(provider, args):
    quick_inventory(provider, args)
