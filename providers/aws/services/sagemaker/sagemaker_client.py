from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.sagemaker.sagemaker_service import SageMaker

sagemaker_client = SageMaker(current_audit_info)
