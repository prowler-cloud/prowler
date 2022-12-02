from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.cloudformation.cloudformation_service import CloudFormation

cloudformation_client = CloudFormation(current_audit_info)
