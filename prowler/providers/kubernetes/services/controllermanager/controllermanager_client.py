from prowler.providers.common.common import global_provider
from prowler.providers.kubernetes.services.controllermanager.controllermanager_service import (
    ControllerManager,
)

controllermanager_client = ControllerManager(global_provider)
