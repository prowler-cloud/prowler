from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.policy.policy_service import Policy

policy_client = Policy(azure_audit_info)
