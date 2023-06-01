from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.dataproc.dataproc_service import Dataproc

dataproc_client = Dataproc(gcp_audit_info)
