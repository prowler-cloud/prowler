from prowler.providers.common.provider import Provider
from prowler.providers.oraclecloud.services.filestorage.filestorage_service import (
    Filestorage,
)

filestorage_client = Filestorage(Provider.get_global_provider())
