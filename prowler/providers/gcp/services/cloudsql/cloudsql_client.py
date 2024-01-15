from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.cloudsql.cloudsql_service import CloudSQL

cloudsql_client = CloudSQL(get_global_provider())
