from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP

cognito_idp_client = CognitoIDP(current_audit_info)
