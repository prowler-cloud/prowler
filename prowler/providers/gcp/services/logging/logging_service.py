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
        self._get_sinks()
        self._get_org_sinks()
        self._get_metrics()

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

    def _get_org_sinks(self):
        """Fetch org-level sinks with includeChildren so child projects are not falsely failed."""
        org_ids = set()
        for project in self.projects.values():
            if project.organization:
                org_ids.add(project.organization.id)

        for org_id in org_ids:
            try:
                request = self.client.sinks().list(parent=f"organizations/{org_id}")
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

                    for sink in response.get("sinks", []):
                        self.sinks.append(
                            Sink(
                                name=sink["name"],
                                destination=sink["destination"],
                                filter=sink.get("filter", "all"),
                                project_id=f"organizations/{org_id}",
                                include_children=sink.get("includeChildren", False),
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
                                bucket_name=metric.get("bucketName", ""),
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


class Sink(BaseModel):
    name: str
    destination: str
    filter: str
    project_id: str
    include_children: bool = False


class Metric(BaseModel):
    name: str
    type: str
    filter: str
    project_id: str
    bucket_name: str = ""


def get_projects_covered_by_aggregated_metric(
    logging_client, monitoring_client, metric_filter
):
    """Return {project_id: metric_name} for scanned projects whose logs are routed,
    via an organization-level sink with includeChildren=True, to a bucket that holds
    a bucket-scoped log metric matching ``metric_filter`` that has an alert policy.

    The CIS GCP logging-metric checks are written per-project, but a common (and
    recommended) topology centralizes monitoring: an org-level aggregated sink ships
    every child project's logs into one bucket, where a single bucket-scoped metric
    + alert covers them all. Without crediting that, those child projects are falsely
    failed. Mirrors the org-sink handling already in ``logging_sink_created`` (#11355).
    """
    # Buckets that hold a matching, alerted, bucket-scoped metric -> metric name.
    bucket_to_metric = {}
    for metric in logging_client.metrics:
        if not getattr(metric, "bucket_name", ""):
            continue
        if metric_filter not in metric.filter:
            continue
        if any(
            metric.name in policy_filter
            for alert_policy in monitoring_client.alert_policies
            for policy_filter in alert_policy.filters
        ):
            bucket_to_metric[metric.bucket_name] = metric.name
    if not bucket_to_metric:
        return {}

    # Org resources whose includeChildren sink targets one of those buckets.
    org_to_metric = {}
    for sink in logging_client.sinks:
        if not getattr(sink, "include_children", False):
            continue
        for bucket, metric_name in bucket_to_metric.items():
            # sink.destination e.g. "logging.googleapis.com/projects/.../buckets/X";
            # metric.bucket_name e.g. "projects/.../buckets/X".
            if sink.destination.endswith(bucket):
                org_to_metric[sink.project_id] = metric_name
                break
    if not org_to_metric:
        return {}

    # Scanned projects sitting under a covering organization.
    covered = {}
    for project_id in logging_client.project_ids:
        project = logging_client.projects.get(project_id)
        organization = getattr(project, "organization", None) if project else None
        if organization and f"organizations/{organization.id}" in org_to_metric:
            covered[project_id] = org_to_metric[f"organizations/{organization.id}"]
    return covered
