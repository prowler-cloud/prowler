from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.ecr.ecr_service import ECR

ecr_client = ECR(current_audit_info)
