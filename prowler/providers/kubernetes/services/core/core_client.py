from prowler.providers.common.common import get_global_provider
from prowler.providers.kubernetes.services.core.core_service import Core

core_client = Core(get_global_provider())
