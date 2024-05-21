from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery

bigquery_client = BigQuery(Provider.get_global_provider())
