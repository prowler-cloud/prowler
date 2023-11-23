from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.logging.logging_service import Logging

logging_client = Logging(global_provider)
