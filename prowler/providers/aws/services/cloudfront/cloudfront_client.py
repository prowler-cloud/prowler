from prowler.providers.aws.services.cloudfront.cloudfront_service import CloudFront
from prowler.providers.common.common import get_global_provider

cloudfront_client = CloudFront(get_global_provider())
