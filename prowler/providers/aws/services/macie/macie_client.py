from prowler.providers.aws.services.macie.macie_service import Macie
from prowler.providers.common.provider import Provider

macie_client = Macie(Provider.get_global_provider())
