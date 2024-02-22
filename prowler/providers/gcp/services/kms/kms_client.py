from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.kms.kms_service import KMS

kms_client = KMS(get_global_provider())
