from prowler.providers.aws.services.s3.s3_service import S3
from prowler.providers.common.common import get_global_provider

s3_client = S3(get_global_provider())
