from prowler.providers.aws.services.kms.kms_service import KMS
from prowler.providers.common.provider import Provider

kms_client = KMS(Provider.get_global_provider())
