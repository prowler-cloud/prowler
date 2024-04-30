from prowler.providers.aws.services.ecr.ecr_service import ECR
from prowler.providers.common.provider import Provider

ecr_client = ECR(Provider.get_global_provider())
