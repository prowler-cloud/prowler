from prowler.providers.aws.services.ecr.ecr_service import ECR
from prowler.providers.common.common import get_global_provider

ecr_client = ECR(get_global_provider())
