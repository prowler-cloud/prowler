from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    CodeArtifact,
)
from prowler.providers.common.provider import Provider

codeartifact_client = CodeArtifact(Provider.get_global_provider())
