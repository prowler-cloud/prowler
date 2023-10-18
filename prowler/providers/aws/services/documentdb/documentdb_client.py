from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.documentdb.documentdb_service import DocumentDB

documentdb_client = DocumentDB(current_audit_info)
