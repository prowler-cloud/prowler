from prowler.providers.common.provider import Provider
from prowler.providers.kubernetes.services.apiserver.apiserver_service import APIServer

apiserver_client = APIServer(Provider.get_global_provider())
