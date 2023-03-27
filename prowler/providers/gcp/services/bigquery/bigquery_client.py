from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery

bigquery_client = BigQuery(gcp_audit_info)
