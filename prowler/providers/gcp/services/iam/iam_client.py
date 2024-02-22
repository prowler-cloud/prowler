from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.iam.iam_service import IAM

iam_client = IAM(get_global_provider())
