from prowler.providers.common.common import get_global_provider
from prowler.providers.kubernetes.services.rbac.rbac_service import Rbac

rbac_client = Rbac(get_global_provider())
