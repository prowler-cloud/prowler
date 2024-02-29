from prowler.providers.azure.services.app.app_service import App
from prowler.providers.common.common import get_global_provider

app_client = App(get_global_provider())
