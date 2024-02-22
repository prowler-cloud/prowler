from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker
from prowler.providers.common.common import get_global_provider

sagemaker_client = SageMaker(get_global_provider())
