from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
from prowler.providers.common.provider import Provider

codebuild_client = Codebuild(Provider.get_global_provider())
