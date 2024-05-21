from prowler.providers.aws.services.cognito.cognito_service import CognitoIdentity
from prowler.providers.common.provider import Provider

cognito_identity_client = CognitoIdentity(Provider.get_global_provider())
