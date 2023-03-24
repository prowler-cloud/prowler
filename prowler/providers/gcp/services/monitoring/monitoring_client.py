from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.monitoring.monitoring_service import Monitoring

monitoring_client = Monitoring(gcp_audit_info)
