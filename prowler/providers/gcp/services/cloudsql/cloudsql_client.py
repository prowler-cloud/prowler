from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.cloudsql.cloudsql_service import CloudSQL

cloudsql_client = CloudSQL(gcp_audit_info)
