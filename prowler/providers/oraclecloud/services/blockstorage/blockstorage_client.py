from prowler.providers.common.provider import Provider
from prowler.providers.oraclecloud.services.blockstorage.blockstorage_service import (
    BlockStorage,
)

blockstorage_client = BlockStorage(Provider.get_global_provider())
