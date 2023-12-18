from importlib import import_module
from typing import Any

providers_prowler_lib_path = "prowler.providers"

# SHARED PROVIDER OBJECT ACROSS ALL PROWLER CODE
global_provider = None


def set_provider(provider, arguments) -> Any:
    provider_class_name = f"{provider.capitalize()}Provider"
    import_module_path = f"prowler.providers.{provider}.azure_provider_testing"
    provider_instance = getattr(import_module(import_module_path), provider_class_name)(
        arguments
    )
    return provider_instance


def get_available_providers() -> list[str]:
    """get_available_providers returns a list of the available providers"""
    providers_list = import_module(f"{providers_prowler_lib_path}")
    print(providers_list.__dict__)
    providers = [
        provider
        for provider in providers_list.__dict__
        if not (provider.startswith("__") or provider.startswith("common"))
    ]
    return providers


def set_global_provider_object(arguments):
    global global_provider
    # make here dynamic import
    common_import_path = (
        f"prowler.providers.{arguments.provider}.{arguments.provider}_provider_new"
    )
    provider_class = f"{arguments.provider.capitalize()}Provider"
    global_provider = getattr(import_module(common_import_path), provider_class)(
        arguments
    )
