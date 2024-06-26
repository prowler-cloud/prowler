from prowler.providers.azure.services.iam.iam_service import IAM
from prowler.providers.common.provider import Provider

iam_client = IAM(Provider.get_global_provider())
