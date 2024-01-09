from prowler.providers.common.common import global_provider
from prowler.providers.kubernetes.services.core.core_service import Core

core_client = Core(global_provider)
