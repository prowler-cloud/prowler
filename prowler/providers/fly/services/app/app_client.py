from prowler.providers.common.provider import Provider
from prowler.providers.fly.services.app.app_service import App

app_client = App(Provider.get_global_provider())
