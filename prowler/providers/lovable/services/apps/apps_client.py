from prowler.providers.common.provider import Provider
from prowler.providers.lovable.services.apps.apps_service import Apps

apps_client = Apps(Provider.get_global_provider())
