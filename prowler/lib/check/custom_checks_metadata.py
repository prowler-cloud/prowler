import sys

import yaml
from jsonschema import validate

from prowler.lib.logger import logger

valid_severities = ["critical", "high", "medium", "low", "informational"]
custom_checks_metadata_schema = {
    "type": "object",
    "properties": {
        "Checks": {
            "type": "object",
            "patternProperties": {
                ".*": {
                    "type": "object",
                    "properties": {
                        "Severity": {
                            "type": "string",
                            "enum": valid_severities,
                        }
                    },
                    "required": ["Severity"],
                    "additionalProperties": False,
                }
            },
            "additionalProperties": False,
        }
    },
    "required": ["Checks"],
    "additionalProperties": False,
}


def parse_custom_checks_metadata_file(provider: str, parse_custom_checks_metadata_file):
    try:
        with open(parse_custom_checks_metadata_file) as f:
            custom_checks_metadata = yaml.safe_load(f)["CustomChecksMetadata"][provider]
            validate(custom_checks_metadata, schema=custom_checks_metadata_schema)
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
            if check_metadata:
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
        try:
            setattr(check_metadata, attribute, custom_metadata[attribute])
        except ValueError:
            pass
        finally:
            return check_metadata
