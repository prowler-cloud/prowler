from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class Logging(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider, api_version="v2")
        self.sinks = []
        self.metrics = []
        self.compute_audit_entries = {}
        self._get_sinks()
        self._get_metrics()
        self._get_compute_audit_entries()

    def _get_sinks(self):
        for project_id in self.project_ids:
            try:
                request = self.client.sinks().list(parent=f"projects/{project_id}")
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

                    for sink in response.get("sinks", []):
                        self.sinks.append(
                            Sink(
                                name=sink["name"],
                                destination=sink["destination"],
                                filter=sink.get("filter", "all"),
                                project_id=project_id,
                            )
                        )

                    request = self.client.sinks().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_metrics(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .metrics()
                    .list(parent=f"projects/{project_id}")
                )
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

                    for metric in response.get("metrics", []):
                        self.metrics.append(
                            Metric(
                                name=metric["name"],
                                type=metric["metricDescriptor"]["type"],
                                filter=metric["filter"],
                                project_id=project_id,
                            )
                        )

                    request = (
                        self.client.projects()
                        .metrics()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_compute_audit_entries(self):
        lookback_days = self.audit_config.get("compute_audit_log_lookback_days", 1)
        start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        timestamp_filter = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        for project_id in self.project_ids:
            try:
                self.compute_audit_entries[project_id] = []
                log_filter = (
                    f'protoPayload.serviceName="compute.googleapis.com" '
                    f'AND logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity" '
                    f'AND timestamp>="{timestamp_filter}"'
                )

                request = self.client.entries().list(
                    body={
                        "resourceNames": [f"projects/{project_id}"],
                        "filter": log_filter,
                        "orderBy": "timestamp desc",
                        "pageSize": 1000,
                    }
                )

                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

                    for entry in response.get("entries", []):
                        proto_payload = entry.get("protoPayload", {})
                        resource = entry.get("resource", {})
                        resource_labels = resource.get("labels", {})

                        auth_info = proto_payload.get("authenticationInfo", {})
                        request_metadata = proto_payload.get("requestMetadata", {})

                        resource_name = resource_labels.get(
                            "instance_id",
                            resource_labels.get(
                                "disk_id",
                                resource_labels.get(
                                    "network_id",
                                    proto_payload.get("resourceName", "unknown"),
                                ),
                            ),
                        )

                        self.compute_audit_entries[project_id].append(
                            AuditLogEntry(
                                insert_id=entry.get("insertId", ""),
                                timestamp=entry.get("timestamp", ""),
                                receive_timestamp=entry.get("receiveTimestamp"),
                                resource_type=resource.get("type", ""),
                                resource_name=resource_name,
                                method_name=proto_payload.get("methodName", ""),
                                service_name=proto_payload.get("serviceName", ""),
                                principal_email=auth_info.get("principalEmail"),
                                caller_ip=request_metadata.get("callerIp"),
                                project_id=project_id,
                            )
                        )

                    if "nextPageToken" in response:
                        request = self.client.entries().list(
                            body={
                                "resourceNames": [f"projects/{project_id}"],
                                "filter": log_filter,
                                "orderBy": "timestamp desc",
                                "pageSize": 1000,
                                "pageToken": response["nextPageToken"],
                            }
                        )
                    else:
                        request = None

            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Sink(BaseModel):
    name: str
    destination: str
    filter: str
    project_id: str


class Metric(BaseModel):
    name: str
    type: str
    filter: str
    project_id: str


class AuditLogEntry(BaseModel):
    insert_id: str
    timestamp: str
    receive_timestamp: Optional[str] = None
    resource_type: str
    resource_name: str
    method_name: str
    service_name: str
    principal_email: Optional[str] = None
    caller_ip: Optional[str] = None
    project_id: str
