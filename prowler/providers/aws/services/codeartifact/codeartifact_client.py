from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    CodeArtifact,
)

codeartifact_client = CodeArtifact(current_audit_info)
