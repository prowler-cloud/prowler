import importlib
import sys

from prowler.lib.logger import logger
from prowler.providers.aws.lib.mutelist.mutelist import parse_mutelist_file


def set_provider_mutelist(provider, audit_info, args):
    """
    set_provider_mutelist configures the mutelist based on the selected provider.
    """
    try:
        # Check if the provider arguments has the mutelist_file
        if hasattr(args, "mutelist_file"):
            # Dynamically get the Provider mutelist handler
            provider_mutelist_function = f"set_{provider}_mutelist"
            mutelist_file = getattr(
                importlib.import_module(__name__), provider_mutelist_function
            )(audit_info, args.mutelist_file)

            return mutelist_file
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)


def set_aws_mutelist(audit_info, mutelist_file):
    # Parse content from Mute List file and get it, if necessary, from S3
    if mutelist_file:
        mutelist_file = parse_mutelist_file(audit_info, mutelist_file)
    else:
        mutelist_file = None
    return mutelist_file
