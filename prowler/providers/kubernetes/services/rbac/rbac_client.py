from prowler.providers.common.provider import Provider
from prowler.providers.kubernetes.services.rbac.rbac_service import Rbac

rbac_client = Rbac(Provider.get_global_provider())
