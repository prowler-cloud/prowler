from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
    CloudStorage,
)

cloudstorage_client = CloudStorage(gcp_audit_info)
