from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery

bigquery_client = BigQuery(get_global_provider())
