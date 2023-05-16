import re

from pydantic import BaseModel

from prowler.providers.aws.lib.arn.error import (
    RoleArnParsingEmptyResource,
    RoleArnParsingFailedMissingFields,
    RoleArnParsingIAMRegionNotEmpty,
    RoleArnParsingInvalidAccountID,
    RoleArnParsingInvalidResourceType,
    RoleArnParsingPartitionEmpty,
    RoleArnParsingServiceNotIAMnorSTS,
)


def parse_iam_credentials_arn(arn):
    # check that arn starts with arn:
    if not arn.startswith("arn:"):
        raise RoleArnParsingFailedMissingFields
    # check for number of fields, must be six
    if len(arn.split(":")) != 6:
        raise RoleArnParsingFailedMissingFields
    else:
        service = arn.split(":")[2]
        # check resource types
        resource_type = get_arn_resource_type(arn, service)

        arn_parsed = Arn(
            partition=arn.split(":")[1],
            service=service,
            region=arn.split(":")[3],
            account_id=arn.split(":")[4],
            resource_type=resource_type,
            resource=arn.split(":")[5],
        )
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


def get_arn_resource_type(arn, service):
    if service == "s3":
        resource_type = "bucket"
    elif service == "sns":
        resource_type = "topic"
    elif service == "sqs":
        resource_type = "queue"
    elif service == "apigateway":
        split_parts = arn.split(":")[5].split("/")
        if "integration" in split_parts and "responses" in split_parts:
            resource_type = "restapis-resources-methods-integration-response"
        elif "documentation" in split_parts and "parts" in split_parts:
            resource_type = "restapis-documentation-parts"
        else:
            resource_type = arn.split(":")[5].split("/")[1]
    else:
        resource_type = arn.split(":")[5].split("/")[0]
    return resource_type


class Arn(BaseModel):
    partition: str
    service: str
    region: str
    account_id: str
    resource: str
    resource_type: str
