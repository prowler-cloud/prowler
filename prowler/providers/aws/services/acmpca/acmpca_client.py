from prowler.providers.aws.services.acmpca.acmpca_service import ACMPCA
from prowler.providers.common.provider import Provider

acmpca_client = ACMPCA(Provider.get_global_provider())
