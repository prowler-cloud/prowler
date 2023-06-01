from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.dns.dns_service import DNS

dns_client = DNS(gcp_audit_info)
