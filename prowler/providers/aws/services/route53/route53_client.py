from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.route53.route53_service import Route53

route53_client = Route53(current_audit_info)
