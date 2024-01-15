from prowler.providers.aws.services.s3.s3_service import S3Control
from prowler.providers.common.common import get_global_provider

s3control_client = S3Control(get_global_provider())
