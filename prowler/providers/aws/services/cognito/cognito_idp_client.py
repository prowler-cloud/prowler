from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP
from prowler.providers.common.provider import Provider

cognito_idp_client = CognitoIDP(Provider.get_global_provider())
