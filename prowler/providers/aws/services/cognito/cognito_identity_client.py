from prowler.providers.aws.services.cognito.cognito_service import CognitoIdentity
from prowler.providers.common.common import get_global_provider

cognito_identity_client = CognitoIdentity(get_global_provider())
