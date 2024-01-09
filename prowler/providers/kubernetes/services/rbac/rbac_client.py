from prowler.providers.common.common import global_provider
from prowler.providers.kubernetes.services.rbac.rbac_service import Rbac

rbac_client = Rbac(global_provider)
