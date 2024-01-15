from prowler.providers.aws.services.iam.iam_service import IAM
from prowler.providers.common.common import get_global_provider

iam_client = IAM(get_global_provider())
