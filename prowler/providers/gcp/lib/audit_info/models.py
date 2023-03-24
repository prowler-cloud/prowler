from dataclasses import dataclass
from typing import Any, Optional

from google.oauth2.credentials import Credentials


@dataclass
class GCP_Audit_Info:
    credentials: Credentials
    project_id: str
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]

    def __init__(self, credentials, project_id, audit_metadata, audit_resources):
        self.credentials = credentials
        self.project_id = project_id
        self.audit_metadata = audit_metadata
        self.audit_resources = audit_resources
