from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.s3.s3_service import S3

s3_client = S3(current_audit_info)
