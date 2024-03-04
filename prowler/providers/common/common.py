import sys
from importlib import import_module

from prowler.lib.logger import logger

providers_path = "prowler.providers"

global_provider = None


def get_available_providers() -> list[str]:
    """get_available_providers returns a list of the available providers"""
    providers_list = import_module(f"{providers_path}")
    providers = [
        provider
        for provider in providers_list.__dict__
        if not (provider.startswith("__") or provider.startswith("common"))
    ]
    return providers


def get_global_provider():
    return global_provider


# TODO: rename to set_global_provider
def set_global_provider_object(arguments):
    try:
        global global_provider

        provider_class_path = (
            f"{providers_path}.{arguments.provider}.{arguments.provider}_provider"
        )
        provider_class_name = f"{arguments.provider.capitalize()}Provider"
        provider_class = getattr(
            import_module(provider_class_path), provider_class_name
        )
        if not isinstance(global_provider, provider_class):
            global_provider = provider_class(arguments)

        return global_provider
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
