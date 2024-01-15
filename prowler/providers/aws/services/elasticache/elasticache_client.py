from prowler.providers.aws.services.elasticache.elasticache_service import ElastiCache
from prowler.providers.common.common import get_global_provider

elasticache_client = ElastiCache(get_global_provider())
