import sys

import yaml
from schema import Schema

from prowler.lib.logger import logger

valid_severities = ["critical", "high", "medium", "low", "informational"]
custom_checks_metadata_schema = Schema(
    {
        "Checks": {
            str: {
                "Severity": str,
            }
        }
    }
)


def parse_custom_checks_metadata_file(provider: str, parse_custom_checks_metadata_file):
    try:
        with open(parse_custom_checks_metadata_file) as f:
            custom_checks_metadata = yaml.safe_load(f)["CustomChecksMetadata"][provider]
            custom_checks_metadata_schema.validate(custom_checks_metadata)
        return custom_checks_metadata
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def update_checks_metadata(bulk_checks_metadata, custom_checks_metadata):
    try:
        # Update checks metadata from CustomChecksMetadata file
        for check, custom_metadata in custom_checks_metadata["Checks"].items():
            check_metadata = bulk_checks_metadata.get(check)
            if check:
                bulk_checks_metadata[check] = update_check_metadata(
                    check_metadata, custom_metadata
                )
        return bulk_checks_metadata
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def update_check_metadata(check_metadata, custom_metadata):
    for attribute in custom_metadata:
        setattr(check_metadata, attribute, custom_metadata[attribute])
    return check_metadata
