from prowler.providers.common.provider import Provider
from prowler.providers.kubernetes.services.core.core_service import Core

core_client = Core(Provider.get_global_provider())
