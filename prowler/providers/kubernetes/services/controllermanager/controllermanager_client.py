from prowler.providers.common.common import get_global_provider
from prowler.providers.kubernetes.services.controllermanager.controllermanager_service import (
    ControllerManager,
)

controllermanager_client = ControllerManager(get_global_provider())
