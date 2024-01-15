from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    CodeArtifact,
)
from prowler.providers.common.common import get_global_provider

codeartifact_client = CodeArtifact(get_global_provider())
