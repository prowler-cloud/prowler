from prowler.providers.aws.services.codepipeline.codepipeline_service import (
    CodePipeline,
)
from prowler.providers.common.provider import Provider

codepipeline_client = CodePipeline(Provider.get_global_provider())
