from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.elb.elb_service import ELB

elb_client = ELB(current_audit_info)
