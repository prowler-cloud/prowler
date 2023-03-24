from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.logging.logging_service import Logging

logging_client = Logging(gcp_audit_info)
