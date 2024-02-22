from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
from prowler.providers.common.common import get_global_provider

codebuild_client = Codebuild(get_global_provider())
