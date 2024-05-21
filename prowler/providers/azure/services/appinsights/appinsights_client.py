from prowler.providers.azure.services.appinsights.appinsights_service import AppInsights
from prowler.providers.common.provider import Provider

appinsights_client = AppInsights(Provider.get_global_provider())
