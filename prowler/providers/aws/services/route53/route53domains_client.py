from prowler.providers.aws.services.route53.route53_service import Route53Domains
from prowler.providers.common.common import get_global_provider

route53domains_client = Route53Domains(get_global_provider())
