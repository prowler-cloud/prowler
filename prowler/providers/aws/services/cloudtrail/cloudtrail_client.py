from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail

cloudtrail_client = Cloudtrail(current_audit_info)
