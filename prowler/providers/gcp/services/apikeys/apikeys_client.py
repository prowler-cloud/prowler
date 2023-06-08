from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.apikeys.apikeys_service import APIKeys

apikeys_client = APIKeys(gcp_audit_info)
