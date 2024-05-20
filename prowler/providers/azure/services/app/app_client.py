from prowler.providers.azure.services.app.app_service import App
from prowler.providers.common.provider import Provider

app_client = App(Provider.get_global_provider())
