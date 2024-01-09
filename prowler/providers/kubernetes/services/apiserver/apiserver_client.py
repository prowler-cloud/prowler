from prowler.providers.common.common import global_provider
from prowler.providers.kubernetes.services.apiserver.apiserver_service import APIServer

apiserver_client = APIServer(global_provider)
