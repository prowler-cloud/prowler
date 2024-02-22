from prowler.providers.aws.services.cloudformation.cloudformation_service import (
    CloudFormation,
)
from prowler.providers.common.common import get_global_provider

cloudformation_client = CloudFormation(get_global_provider())
