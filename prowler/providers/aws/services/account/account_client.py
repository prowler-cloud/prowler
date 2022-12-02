from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.account.account_service import Account

account_client = Account(current_audit_info)
