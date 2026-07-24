from prowler.providers.common.provider import Provider
from prowler.providers.oracledb.services.encryption.encryption_service import (
    Encryption,
)

encryption_client = Encryption(Provider.get_global_provider())
