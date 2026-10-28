from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.appengine.appengine_service import AppEngine

appengine_client = AppEngine(Provider.get_global_provider())
