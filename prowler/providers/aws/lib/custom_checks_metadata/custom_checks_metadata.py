import sys

import yaml
from schema import Optional, Schema

from prowler.lib.logger import logger

custom_checks_metadata_schema = Schema(
    {
        "Checks": {
            str: {
                "Severity": [str],
                Optional("RelatedUrl"): [str],
            }
        }
    }
)


def parse_custom_checks_metadata_file(parse_custom_checks_metadata_file):
    try:
        with open(parse_custom_checks_metadata_file) as f:
            custom_checks_metadata = yaml.safe_load(f)["CustomChecksMetadata"]
        try:
            custom_checks_metadata_schema.validate(custom_checks_metadata)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__} -- CustomChecksMetadata YAML is malformed - {error}[{error.__traceback__.tb_lineno}]"
            )
            sys.exit(1)
        return custom_checks_metadata
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)
