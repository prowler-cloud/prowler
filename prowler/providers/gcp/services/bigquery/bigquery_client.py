from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery

bigquery_client = BigQuery(global_provider)
