from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.kms.kms_service import KMS

kms_client = KMS(Provider.get_global_provider())
