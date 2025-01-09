import sys

import yaml
from jsonschema import validate

from prowler.lib.check.models import Severity
from prowler.lib.logger import logger

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
                            "enum": [severity.value for severity in Severity],
                        },
                        "CheckTitle": {
                            "type": "string",
                        },
                        "Description": {
                            "type": "string",
                        },
                        "Risk": {
                            "type": "string",
                        },
                        "RelatedUrl": {
                            "type": "string",
                        },
                        "Remediation": {
                            "type": "object",
                            "properties": {
                                "Code": {
                                    "type": "object",
                                    "properties": {
                                        "CLI": {
                                            "type": "string",
                                        },
                                        "NativeIaC": {
                                            "type": "string",
                                        },
                                        "Other": {
                                            "type": "string",
                                        },
                                        "Terraform": {
                                            "type": "string",
                                        },
                                    },
                                },
                                "Recommendation": {
                                    "type": "object",
                                    "properties": {
                                        "Text": {
                                            "type": "string",
                                        },
                                        "Url": {
                                            "type": "string",
                                        },
                                    },
                                    "additionalProperties": False,
                                },
                            },
                            "additionalProperties": False,
                        },
                    },
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
    """parse_custom_checks_metadata_file returns the custom_checks_metadata object if it is valid, otherwise aborts the execution returning the ValidationError."""
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
    """update_checks_metadata returns the bulk_checks_metadata with the check's metadata updated based on the custom_checks_metadata provided."""
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
    """update_check_metadata updates the check_metadata fields present in the custom_metadata and returns the updated version of the check_metadata. If some field is not present or valid the check_metadata is returned with the original fields."""
    try:
        if custom_metadata:
            for attribute in custom_metadata:
                if attribute == "Remediation":
                    for remediation_attribute in custom_metadata[attribute]:
                        update_check_metadata_remediation(
                            check_metadata,
                            custom_metadata,
                            attribute,
                            remediation_attribute,
                        )
                else:
                    try:
                        setattr(check_metadata, attribute, custom_metadata[attribute])
                    except ValueError:
                        pass
    finally:
        return check_metadata


def update_check_metadata_remediation(
    check_metadata, custom_metadata, attribute, remediation_attribute
):
    if remediation_attribute == "Code":
        for code_attribute in custom_metadata[attribute][remediation_attribute]:
            try:
                setattr(
                    check_metadata.Remediation.Code,
                    code_attribute,
                    custom_metadata[attribute][remediation_attribute][code_attribute],
                )
            except ValueError:
                pass
    elif remediation_attribute == "Recommendation":
        for recommendation_attribute in custom_metadata[attribute][
            remediation_attribute
        ]:
            try:
                setattr(
                    check_metadata.Remediation.Recommendation,
                    recommendation_attribute,
                    custom_metadata[attribute][remediation_attribute][
                        recommendation_attribute
                    ],
                )
            except ValueError:
                pass
