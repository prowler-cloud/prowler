from importlib import import_module

providers_prowler_lib_path = "prowler.providers"


def get_available_providers():
    providers_list = import_module(f"{providers_prowler_lib_path}")
    providers = [
        provider
        for provider in providers_list.__dict__
        if not (provider.startswith("__") or provider.startswith("common"))
    ]
    return providers
