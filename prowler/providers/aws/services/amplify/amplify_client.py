from prowler.providers.aws.services.amplify.amplify_service import Amplify
from prowler.providers.common.provider import Provider

amplify_client = Amplify(Provider.get_global_provider())
