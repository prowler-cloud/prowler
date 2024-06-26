from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker
from prowler.providers.common.provider import Provider

sagemaker_client = SageMaker(Provider.get_global_provider())
