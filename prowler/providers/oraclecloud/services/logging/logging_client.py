"""OCI Logging Client Module."""

from prowler.providers.common.provider import Provider
from prowler.providers.oraclecloud.services.logging.logging_service import Logging

logging_client = Logging(Provider.get_global_provider())
