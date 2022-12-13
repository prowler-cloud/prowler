from arnparse import arnparse

from prowler.providers.aws.lib.arn.error import (
    RoleArnParsingEmptyResource,
    RoleArnParsingFailedMissingFields,
    RoleArnParsingIAMRegionNotEmpty,
    RoleArnParsingInvalidAccountID,
    RoleArnParsingInvalidResourceType,
    RoleArnParsingPartitionEmpty,
    RoleArnParsingServiceNotIAM,
)


def arn_parsing(arn):
    # check for number of fields, must be six
    if len(arn.split(":")) != 6:
        raise RoleArnParsingFailedMissingFields
    else:
        arn_parsed = arnparse(arn)
        # First check if region is empty (in IAM arns region is always empty)
        if arn_parsed.region is not None:
            raise RoleArnParsingIAMRegionNotEmpty
        else:
            # check if needed fields are filled:
            # - partition
            # - service
            # - account_id
            # - resource_type
            # - resource
            if arn_parsed.partition is None:
                raise RoleArnParsingPartitionEmpty
            elif arn_parsed.service != "iam":
                raise RoleArnParsingServiceNotIAM
            elif (
                arn_parsed.account_id is None
                or len(arn_parsed.account_id) != 12
                or not arn_parsed.account_id.isnumeric()
            ):
                raise RoleArnParsingInvalidAccountID
            elif arn_parsed.resource_type != "role":
                raise RoleArnParsingInvalidResourceType
            elif arn_parsed.resource == "":
                raise RoleArnParsingEmptyResource
            else:
                return arn_parsed
