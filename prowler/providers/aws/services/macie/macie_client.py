from prowler.providers.aws.services.macie.macie_service import Macie
from prowler.providers.common.common import get_global_provider

macie_client = Macie(get_global_provider())
