from prowler.providers.aws.services.memorydb.memorydb_service import MemoryDB
from prowler.providers.common.provider import Provider

memorydb_client = MemoryDB(Provider.get_global_provider())
