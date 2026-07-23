from prowler.providers.common.provider import Provider
from prowler.providers.oracledb.services.configuration.configuration_service import (
    Configuration,
)

configuration_client = Configuration(Provider.get_global_provider())
