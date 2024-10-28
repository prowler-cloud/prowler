import os
import re
from argparse import ArgumentTypeError

from prowler.providers.aws.exceptions.exceptions import (
    AWSIAMRoleARNEmptyResourceError,
    AWSIAMRoleARNInvalidAccountIDError,
    AWSIAMRoleARNInvalidResourceTypeError,
    AWSIAMRoleARNPartitionEmptyError,
    AWSIAMRoleARNRegionNotEmtpyError,
    AWSIAMRoleARNServiceNotIAMnorSTSError,
)
from prowler.providers.aws.lib.arn.models import ARN


def arn_type(arn: str) -> bool:
    """arn_type returns a string ARN if it is valid and raises an argparse.ArgumentError if not."""
    if not is_valid_arn(arn):
        raise ArgumentTypeError(f"Invalid ARN {arn}")
    return arn


# TODO: review this function just to parse the ARN not to re-instantiate it
def parse_iam_credentials_arn(arn: str) -> ARN:
    arn_parsed = ARN(arn)
    # First check if region is empty (in IAM ARN's region is always empty)
    if arn_parsed.region:
        raise AWSIAMRoleARNRegionNotEmtpyError(file=os.path.basename(__file__))
    else:
        # check if needed fields are filled:
        # - partition
        # - service
        # - account_id
        # - resource_type
        # - resource
        if arn_parsed.partition is None or arn_parsed.partition == "":
            raise AWSIAMRoleARNPartitionEmptyError(file=os.path.basename(__file__))
        elif arn_parsed.service != "iam" and arn_parsed.service != "sts":
            raise AWSIAMRoleARNServiceNotIAMnorSTSError(file=os.path.basename(__file__))
        elif (
            arn_parsed.account_id is None
            or len(arn_parsed.account_id) != 12
            or not arn_parsed.account_id.isnumeric()
        ):
            raise AWSIAMRoleARNInvalidAccountIDError(file=os.path.basename(__file__))
        elif (
            arn_parsed.resource_type != "role"
            and arn_parsed.resource_type != "user"
            and arn_parsed.resource_type != "assumed-role"
            and arn_parsed.resource_type != "root"
            and arn_parsed.resource_type != "federated-user"
        ):
            raise AWSIAMRoleARNInvalidResourceTypeError(file=os.path.basename(__file__))
        elif arn_parsed.resource == "":
            raise AWSIAMRoleARNEmptyResourceError(file=os.path.basename(__file__))
        else:
            return arn_parsed


def is_valid_arn(arn: str) -> bool:
    """is_valid_arn returns True or False whether the given AWS ARN (Amazon Resource Name) is valid or not."""
    regex = r"^arn:aws(-cn|-us-gov|-iso|-iso-b)?:[a-zA-Z0-9\-]+:([a-z]{2}-[a-z]+-\d{1})?:(\d{12})?:[a-zA-Z0-9\-_\/:\.\*]+(:\d+)?$"
    return re.match(regex, arn) is not None
