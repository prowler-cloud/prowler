from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.s3.s3_service import S3, S3Control

s3_client = S3(current_audit_info)
s3control_client = S3Control(current_audit_info)
