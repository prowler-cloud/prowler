from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.elasticache.elasticache_service import Elasticache

elasticache_client = Elasticache(current_audit_info)
