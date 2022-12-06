from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.s3.s3_service import S3Control

s3control_client = S3Control(current_audit_info)
