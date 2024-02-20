from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.neptune.neptune_service import Neptune

neptune_client = Neptune(current_audit_info)
