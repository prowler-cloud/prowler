import re

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService
from prowler.providers.gcp.services.monitoring.monitoring_service import Monitoring


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


# A positive selector of the Admin Activity stream: a ``logName`` predicate
# (``:`` has-substring or ``=`` equals) or a ``log_id()`` call. Written verbose
# so each fragment stays legible; ``(?![a-z_])`` keeps a longer stream name
# (``.../activity_v2``) from impersonating Admin Activity.
_ACTIVITY_SELECTOR = re.compile(
    r"""
    (?: logName \s* [:=] \s* | log_id \s* \( \s* )   # logName: / logName= / log_id(
    ["']? [^"'\s)]*                                  # optional quote, then path prefix
    cloudaudit\.googleapis\.com/activity (?![a-z_])  # the Admin Activity stream itself
    """,
    re.IGNORECASE | re.VERBOSE,
)

# The same selector for *any* Cloud Audit stream (activity, data_access,
# system_event, policy, access_transparency, …). Used to strip the OR-combined
# audit clauses so we can prove nothing restrictive is left over.
_CLOUDAUDIT_SELECTOR = re.compile(
    r"""
    (?: logName \s* [:=] \s* | log_id \s* \( \s* )   # logName: / logName= / log_id(
    ["']? [^"'\s)]*                                  # optional quote, then path prefix
    cloudaudit\.googleapis\.com/[a-z_]+              # any cloudaudit stream
    ["']? \s* \)?                                    # optional closing quote / paren
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Operators that exclude or narrow coverage. Any of these means we cannot prove
# the sink delivers the *whole* Admin Activity stream, so it is not credited.
_NEGATION_OR_RESTRICTION = re.compile(
    r"""
      \bNOT\b                       # NOT exclusion
    | \bAND\b                       # AND conjunction (restriction)
    | != | !:                       # "!=" / "!:" inequality
    | (?:^|[\s(]) -\s* [A-Za-z_]    # leading "-" exclusion operator
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _sink_delivers_activity_logs(sink_filter: str) -> bool:
    """True only when a sink's filter *provably* exports the full Admin Activity
    audit stream (or everything).

    Crediting flips a child project to PASS on a CIS security control, so the
    match is deliberately conservative: a false FAIL is safe, a false PASS is
    not. A non-``"all"`` filter is credited only when

      1. it positively selects the Admin Activity stream
         (``logName:.../activity``, ``logName="...activity"`` or
         ``log_id("...activity")``);
      2. it carries no operator that excludes or narrows the stream — ``NOT`` /
         ``-`` / ``!=`` (negation) or ``AND`` (restriction); and
      3. nothing but ``OR``-combined Cloud Audit selectors remains once those are
         stripped — an ``OR`` only widens coverage, but any leftover predicate
         (``severity>=ERROR``, ``resource.type=...``) could narrow it.

    Sink filters encode the stream URL-encoded (``...%2Factivity``) or as a path
    — normalize before matching.
    """
    if not sink_filter or sink_filter.strip().lower() == "all":
        return True
    normalized = sink_filter.replace("%2F", "/").replace("%2f", "/")
    # 1. The Admin Activity stream must be positively selected.
    if not _ACTIVITY_SELECTOR.search(normalized):
        return False
    # 2. No operator may exclude or narrow that coverage.
    if _NEGATION_OR_RESTRICTION.search(normalized):
        return False
    # 3. Only OR-combined audit selectors may remain — strip them and the OR
    #    glue; anything left is a predicate we cannot prove is full-coverage.
    remainder = _CLOUDAUDIT_SELECTOR.sub(" ", normalized)
    remainder = re.sub(r"\bOR\b|[()\s]", " ", remainder, flags=re.IGNORECASE)
    return remainder.strip() == ""


def get_projects_covered_by_aggregated_metric(
    logging_client: Logging,
    monitoring_client: Monitoring,
    metric_filter: str,
) -> dict[str, str]:
    """Return {project_id: metric_name} for scanned projects whose logs are routed,
    via an organization-level sink with includeChildren=True, to a bucket that holds
    a bucket-scoped log metric matching ``metric_filter`` that has an alert policy.

    The CIS GCP logging-metric checks are written per-project, but a common (and
    recommended) topology centralizes monitoring: an org-level aggregated sink ships
    every child project's logs into one bucket, where a single bucket-scoped metric
    + alert covers them all. Without crediting that, those child projects are falsely
    failed. Mirrors the org-sink handling already in ``logging_sink_created`` (#11355).

    A sink is credited when it exports everything (``filter == "all"``) or when its
    filter carries the Admin Activity audit stream — the only stream the CIS metric
    filters can match (see ``_sink_delivers_activity_logs``).
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
        if not _sink_delivers_activity_logs(getattr(sink, "filter", "all")):
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
