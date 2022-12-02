from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.secretsmanager.secretsmanager_service import SecretsManager

secretsmanager_client = SecretsManager(current_audit_info)
