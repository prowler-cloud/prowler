from prowler.providers.aws.services.cloudformation.cloudformation_service import (
    CloudFormation,
)
from prowler.providers.common.provider import Provider

cloudformation_client = CloudFormation(Provider.get_global_provider())
