from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.kms.kms_service import KMS

kms_client = KMS(global_provider)
