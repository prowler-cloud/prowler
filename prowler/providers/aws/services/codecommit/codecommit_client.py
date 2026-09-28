from prowler.providers.aws.services.codecommit.codecommit_service import CodeCommit
from prowler.providers.common.provider import Provider

codecommit_client = CodeCommit(Provider.get_global_provider())
