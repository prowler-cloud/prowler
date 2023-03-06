import importlib
import sys

from prowler.lib.logger import logger
from prowler.providers.aws.lib.allowlist.allowlist import parse_allowlist_file


def set_provider_allowlist(provider, audit_info, allowlist_file):
    """
    set_provider_allowlist configures the allowlist based on the selected provider.
    """
    try:
        # Dynamically get the Provider allowlist handler
        provider_allowlist_function = f"set_{provider}_allowlist"
        allowlist_file = getattr(
            importlib.import_module(__name__), provider_allowlist_function
        )(audit_info, allowlist_file)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)
    else:
        return allowlist_file


def set_aws_allowlist(audit_info, allowlist_file):
    # Parse content from Allowlist file and get it, if necessary, from S3
    if allowlist_file:
        allowlist_file = parse_allowlist_file(audit_info, allowlist_file)
    else:
        allowlist_file = None
    return allowlist_file
