from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.cloudsql.cloudsql_service import CloudSQL

cloudsql_client = CloudSQL(Provider.get_global_provider())
