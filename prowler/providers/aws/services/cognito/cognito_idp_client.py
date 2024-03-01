from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP
from prowler.providers.common.common import get_global_provider

cognito_idp_client = CognitoIDP(get_global_provider())
