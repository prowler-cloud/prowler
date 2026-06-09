from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.application.application_service import Application

application_client = Application(Provider.get_global_provider())
