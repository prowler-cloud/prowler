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
