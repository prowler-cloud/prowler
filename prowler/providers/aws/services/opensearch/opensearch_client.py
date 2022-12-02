from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.opensearch.opensearch_service import OpenSearchService

opensearch_client = OpenSearchService(current_audit_info)
