from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.athena.athena_service import Athena

athena_client = Athena(current_audit_info)
