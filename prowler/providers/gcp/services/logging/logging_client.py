from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.logging.logging_service import Logging

logging_client = Logging(get_global_provider())
