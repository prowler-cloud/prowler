from prowler.providers.azure.services.appinsights.appinsights_service import AppInsights
from prowler.providers.common.common import get_global_provider

appinsights_client = AppInsights(get_global_provider())
