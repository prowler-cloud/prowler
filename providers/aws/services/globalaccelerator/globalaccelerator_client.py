from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.globalaccelerator.globalaccelerator_service import (
    GlobalAccelerator,
)

globalaccelerator_client = GlobalAccelerator(current_audit_info)
