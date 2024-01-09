from dataclasses import dataclass
from typing import Any, Optional

from kubernetes import client


@dataclass
class Kubernetes_Audit_Info:
    api_client: client.ApiClient
    context: Optional[str]
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: Optional[dict]

    def __init__(
        self,
        api_client,
        context,
        audit_metadata,
        audit_resources,
        audit_config,
    ):
        self.api_client = api_client
        self.context = context
        self.audit_metadata = audit_metadata
        self.audit_resources = audit_resources
        self.audit_config = audit_config
