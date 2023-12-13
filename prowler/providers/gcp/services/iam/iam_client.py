from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.iam.iam_service import IAM

iam_client = IAM(global_provider)
