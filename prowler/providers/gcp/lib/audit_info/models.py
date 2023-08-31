from dataclasses import dataclass
from typing import Any, Optional

from google.oauth2.credentials import Credentials


@dataclass
class GCP_Audit_Info:
    credentials: Credentials
    default_project_id: str
    project_ids: list
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: Optional[dict]

    def __init__(
        self,
        credentials,
        default_project_id,
        project_ids,
        audit_metadata,
        audit_resources,
        audit_config,
    ):
        self.credentials = credentials
        self.default_project_id = default_project_id
        self.project_ids = project_ids
        self.audit_metadata = audit_metadata
        self.audit_resources = audit_resources
        self.audit_config = audit_config
