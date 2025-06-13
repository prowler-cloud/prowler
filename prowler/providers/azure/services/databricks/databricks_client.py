from prowler.providers.azure.services.databricks.databricks_service import Databricks
from prowler.providers.common.provider import Provider

databricks_client = Databricks(Provider.get_global_provider())
