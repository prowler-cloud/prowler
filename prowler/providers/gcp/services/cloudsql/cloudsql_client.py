from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.cloudsql.cloudsql_service import CloudSQL

cloudsql_client = CloudSQL(global_provider)
