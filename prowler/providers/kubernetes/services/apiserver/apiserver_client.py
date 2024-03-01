from prowler.providers.common.common import get_global_provider
from prowler.providers.kubernetes.services.apiserver.apiserver_service import APIServer

apiserver_client = APIServer(get_global_provider())
