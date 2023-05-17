import re

from prowler.providers.aws.lib.arn.error import (
    RoleArnParsingEmptyResource,
    RoleArnParsingIAMRegionNotEmpty,
    RoleArnParsingInvalidAccountID,
    RoleArnParsingInvalidResourceType,
    RoleArnParsingPartitionEmpty,
    RoleArnParsingServiceNotIAMnorSTS,
)
from prowler.providers.aws.lib.arn.models import ARN


def parse_iam_credentials_arn(arn: str) -> ARN:
    arn_parsed = ARN(arn)
    # First check if region is empty (in IAM ARN's region is always empty)
    if arn_parsed.region:
        raise RoleArnParsingIAMRegionNotEmpty
    else:
        # check if needed fields are filled:
        # - partition
        # - service
        # - account_id
        # - resource_type
        # - resource
        if arn_parsed.partition is None or arn_parsed.partition == "":
            raise RoleArnParsingPartitionEmpty
        elif arn_parsed.service != "iam" and arn_parsed.service != "sts":
            raise RoleArnParsingServiceNotIAMnorSTS
        elif (
            arn_parsed.account_id is None
            or len(arn_parsed.account_id) != 12
            or not arn_parsed.account_id.isnumeric()
        ):
            raise RoleArnParsingInvalidAccountID
        elif (
            arn_parsed.resource_type != "role"
            and arn_parsed.resource_type != "user"
            and arn_parsed.resource_type != "assumed-role"
        ):
            raise RoleArnParsingInvalidResourceType
        elif arn_parsed.resource == "":
            raise RoleArnParsingEmptyResource
        else:
            return arn_parsed


def is_valid_arn(arn: str) -> bool:
    """is_valid_arn returns True or False whether the given AWS ARN (Amazon Resource Name) is valid or not."""
    regex = r"^arn:aws(-cn|-us-gov)?:[a-zA-Z0-9\-]+:([a-z]{2}-[a-z]+-\d{1})?:(\d{12})?:[a-zA-Z0-9\-_\/]+(:\d+)?$"
    return re.match(regex, arn) is not None
