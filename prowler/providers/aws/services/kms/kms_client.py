from prowler.providers.aws.services.kms.kms_service import KMS
from prowler.providers.common.common import get_global_provider

kms_client = KMS(get_global_provider())
