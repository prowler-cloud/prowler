from prowler.providers.aws.services.route53.route53_service import Route53
from prowler.providers.common.common import get_global_provider

route53_client = Route53(get_global_provider())
