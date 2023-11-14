import importlib
import sys

from prowler.lib.logger import logger
from prowler.providers.aws.lib.custom_checks_metadata.custom_checks_metadata import (
    parse_custom_checks_metadata_file,
)


def set_provider_custom_checks_metadata(provider, args):
    """
    set_custom_checks_metadata overides the metadata based on the selected provider.
    """
    try:
        # Check if the provider arguments has the allowlist_file
        if hasattr(args, "custom_checks_metadata_file"):
            # Dynamically get the Provider custom_checks metadata handler
            provider_custom_checks_metadata_function = (
                f"set_{provider}_custom_checks_metadata"
            )
            custom_checks_metadata_file = getattr(
                importlib.import_module(__name__),
                provider_custom_checks_metadata_function,
            )(args.custom_checks_metadata_file)

            return custom_checks_metadata_file
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)


def set_aws_custom_checks_metadata(custom_checks_metadata_file):
    # Parse content from Allowlist file
    if custom_checks_metadata_file:
        custom_checks_metadata_file = parse_custom_checks_metadata_file(
            custom_checks_metadata_file
        )
    else:
        custom_checks_metadata_file = None
    return custom_checks_metadata_file


def update_checks_metadata(bulk_checks_metadata, custom_checks_metadata_file):
    # Update checks metadata from CustomChecksMetadata file
    custom_checks_metadata_file_checks = custom_checks_metadata_file["Checks"]
    for check in custom_checks_metadata_file_checks:
        if bulk_checks_metadata.get(check):
            bulk_checks_metadata[check].Severity = custom_checks_metadata_file_checks[
                check
            ]["Severity"]
    return bulk_checks_metadata
