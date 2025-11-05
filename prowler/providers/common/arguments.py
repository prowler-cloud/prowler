import sys
from argparse import Namespace
from importlib import import_module

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider, providers_path

provider_arguments_lib_path = "lib.arguments.arguments"
validate_provider_arguments_function = "validate_arguments"
init_provider_arguments_function = "init_parser"


def init_providers_parser(self):
    """init_providers_parser calls the provider init_parser function to load all the arguments and flags. Receives a ProwlerArgumentParser object"""
    # We need to call the arguments parser for each provider
    providers = Provider.get_available_providers()
    for provider in providers:
        try:
            getattr(
                import_module(
                    f"{providers_path}.{provider}.{provider_arguments_lib_path}"
                ),
                init_provider_arguments_function,
            )(self)
        except Exception as error:
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
