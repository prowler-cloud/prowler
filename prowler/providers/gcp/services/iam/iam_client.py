from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.iam.iam_service import IAM

iam_client = IAM(Provider.get_global_provider())
