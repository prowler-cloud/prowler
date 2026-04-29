import datetime
from concurrent.futures import as_completed
from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Codebuild(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.projects = {}
        self.__threading_call__(self._list_projects)
        self.__threading_call__(self._list_builds_for_project)
        self.__threading_call__(self._batch_get_builds)
        self.__threading_call__(self._batch_get_projects)
        self.report_groups = {}
        self.__threading_call__(self._list_report_groups)
        self.__threading_call__(
            self._batch_get_report_groups, self.report_groups.values()
        )

    def _list_projects(self, regional_client):
        logger.info("Codebuild - Listing projects...")
        try:
            list_projects_paginator = regional_client.get_paginator("list_projects")
            for page in list_projects_paginator.paginate():
                for project in page["projects"]:
                    project_arn = f"arn:{self.audited_partition}:codebuild:{regional_client.region}:{self.audited_account}:project/{project}"
                    if not self.audit_resources or (
                        is_resource_filtered(project_arn, self.audit_resources)
                    ):
                        self.projects[project_arn] = Project(
                            name=project,
                            arn=project_arn,
                            region=regional_client.region,
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _fetch_project_last_build(self, regional_client, project):
        try:
            build_ids = regional_client.list_builds_for_project(
                projectName=project.name
            ).get("ids", [])
            if len(build_ids) > 0:
                project.last_build = Build(id=build_ids[0])
        except Exception as error:
            # Catch broadly so a failure on a single project (API error,
            # connection timeout, etc.) does not stop processing the
            # remaining projects in this region. Throttling is handled
            # by the shared botocore standard retry policy configured
            # at the provider level.
            logger.error(
                f"{project.region}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_builds_for_project(self, regional_client):
        logger.info("Codebuild - Listing builds...")
        try:
            regional_projects = [
                project
                for project in self.projects.values()
                if project.region == regional_client.region
            ]

            # list_builds_for_project has no batch API equivalent, so reuse the
            # shared thread pool to issue per-project calls in parallel within
            # this region — preserving the wall-clock performance of the
            # previous implementation.
            futures = [
                self.thread_pool.submit(
                    self._fetch_project_last_build, regional_client, project
                )
                for project in regional_projects
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _batch_get_builds(self, regional_client):
        logger.info("Codebuild - Getting builds...")
        try:
            # Collect all build IDs for this region
            build_id_to_project = {}
            for project in self.projects.values():
                if project.region == regional_client.region and project.last_build and project.last_build.id:
                    build_id_to_project[project.last_build.id] = project

            if not build_id_to_project:
                return

            build_ids = list(build_id_to_project.keys())

            # batch_get_builds supports up to 100 IDs per call
            for i in range(0, len(build_ids), 100):
                batch = build_ids[i : i + 100]
                response = regional_client.batch_get_builds(ids=batch)
                for build_info in response.get("builds", []):
                    build_id = build_info.get("id")
                    if build_id in build_id_to_project:
                        end_time = build_info.get("endTime")
                        if end_time:
                            build_id_to_project[build_id].last_invoked_time = end_time
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _batch_get_projects(self, regional_client):
        logger.info("Codebuild - Getting projects...")
        try:
            # Collect all project names for this region
            regional_projects = {
                arn: project
                for arn, project in self.projects.items()
                if project.region == regional_client.region
            }
            if not regional_projects:
                return

            project_names = [
                project.name for project in regional_projects.values()
            ]

            # batch_get_projects supports up to 100 names per call
            for i in range(0, len(project_names), 100):
                batch = project_names[i : i + 100]
                response = regional_client.batch_get_projects(names=batch)
                for project_info in response.get("projects", []):
                    project_arn = project_info.get("arn")
                    if project_arn in regional_projects:
                        self._parse_project_info(
                            regional_projects[project_arn], project_info
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _parse_project_info(self, project, project_info):
        try:
            project.buildspec = project_info["source"].get("buildspec")
            if project_info["source"]["type"] != "NO_SOURCE":
                project.source = Source(
                    type=project_info["source"]["type"],
                    location=project_info["source"].get("location", ""),
                )
            project.secondary_sources = []
            for secondary_source in project_info.get("secondarySources", []):
                source_obj = Source(
                    type=secondary_source["type"],
                    location=secondary_source.get("location", ""),
                )
                project.secondary_sources.append(source_obj)
            environment = project_info.get("environment", {})
            env_vars = environment.get("environmentVariables", [])
            project.environment_variables = [
                EnvironmentVariable(**var) for var in env_vars
            ]
            project.buildspec = project_info.get("source", {}).get("buildspec", "")
            s3_logs = project_info.get("logsConfig", {}).get("s3Logs", {})
            project.s3_logs = s3Logs(
                enabled=(
                    True if s3_logs.get("status", "DISABLED") == "ENABLED" else False
                ),
                bucket_location=s3_logs.get("location", ""),
                encrypted=(not s3_logs.get("encryptionDisabled", False)),
            )
            cloudwatch_logs = project_info.get("logsConfig", {}).get(
                "cloudWatchLogs", {}
            )
            project.cloudwatch_logs = CloudWatchLogs(
                enabled=(
                    True
                    if cloudwatch_logs.get("status", "DISABLED") == "ENABLED"
                    else False
                ),
                group_name=cloudwatch_logs.get("groupName", ""),
                stream_name=cloudwatch_logs.get("streamName", ""),
            )
            project.tags = project_info.get("tags", [])
            project.service_role_arn = project_info.get("serviceRole", "")
            project.project_visibility = project_info.get("projectVisibility", "")

            # Extract webhook configuration
            webhook_data = project_info.get("webhook")
            if webhook_data:
                filter_groups = []
                for fg in webhook_data.get("filterGroups", []):
                    filters = []
                    for f in fg:
                        filters.append(
                            WebhookFilter(
                                type=f.get("type", ""),
                                pattern=f.get("pattern", ""),
                                exclude_matched_pattern=f.get(
                                    "excludeMatchedPattern", False
                                ),
                            )
                        )
                    filter_groups.append(WebhookFilterGroup(filters=filters))

                project.webhook = Webhook(
                    filter_groups=filter_groups,
                    branch_filter=webhook_data.get("branchFilter"),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_report_groups(self, regional_client):
        logger.info("Codebuild - Listing report groups...")
        try:
            list_report_groups_paginator = regional_client.get_paginator(
                "list_report_groups"
            )
            for page in list_report_groups_paginator.paginate():
                for report_group_arn in page["reportGroups"]:
                    if not self.audit_resources or (
                        is_resource_filtered(report_group_arn, self.audit_resources)
                    ):
                        self.report_groups[report_group_arn] = ReportGroup(
                            arn=report_group_arn,
                            name=report_group_arn.split(":")[-1].split("/")[-1],
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _batch_get_report_groups(self, report_group):
        logger.info("Codebuild - Getting report groups...")
        try:
            report_group_info = self.regional_clients[
                report_group.region
            ].batch_get_report_groups(reportGroupArns=[report_group.arn])[
                "reportGroups"
            ][
                0
            ]

            report_group.status = report_group_info.get("status", "DELETING")

            export_config = report_group_info.get("exportConfig", {})
            if export_config:
                s3_destination = export_config.get("s3Destination", {})
                report_group.export_config = ExportConfig(
                    type=export_config.get("exportConfigType", "NO_EXPORT"),
                    bucket_location=(
                        f"s3://{s3_destination.get('bucket', '')}/{s3_destination.get('path', '')}"
                        if s3_destination.get("bucket", "")
                        else ""
                    ),
                    encryption_key=s3_destination.get("encryptionKey", ""),
                    encrypted=(not s3_destination.get("encryptionDisabled", True)),
                )

            report_group.tags = report_group_info.get("tags", [])
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Build(BaseModel):
    id: str


class Source(BaseModel):
    type: str
    location: str


class EnvironmentVariable(BaseModel):
    name: str
    value: str
    type: str


class s3Logs(BaseModel):
    enabled: bool
    bucket_location: str
    encrypted: bool


class CloudWatchLogs(BaseModel):
    enabled: bool
    group_name: str
    stream_name: str


class WebhookFilter(BaseModel):
    """Represents a single filter in a webhook filter group."""

    type: str  # ACTOR_ACCOUNT_ID, HEAD_REF, BASE_REF, EVENT, etc.
    pattern: str
    exclude_matched_pattern: bool = False


class WebhookFilterGroup(BaseModel):
    """Represents a group of filters (AND logic within group)."""

    filters: List[WebhookFilter] = []


class Webhook(BaseModel):
    """Represents the webhook configuration for a CodeBuild project."""

    filter_groups: List[WebhookFilterGroup] = []
    branch_filter: Optional[str] = None


class Project(BaseModel):
    name: str
    arn: str
    region: str
    last_build: Optional[Build] = None
    last_invoked_time: Optional[datetime.datetime] = None
    buildspec: Optional[str] = None
    source: Optional[Source] = None
    secondary_sources: Optional[list[Source]] = []
    service_role_arn: Optional[str] = None
    environment_variables: Optional[List[EnvironmentVariable]]
    s3_logs: Optional[s3Logs]
    cloudwatch_logs: Optional[CloudWatchLogs]
    tags: Optional[list]
    project_visibility: Optional[str] = None
    webhook: Optional[Webhook] = None


class ExportConfig(BaseModel):
    type: str
    bucket_location: str
    encryption_key: str
    encrypted: bool


class ReportGroup(BaseModel):
    arn: str
    name: str
    region: str
    status: Optional[str] = None
    export_config: Optional[ExportConfig] = None
    tags: Optional[list] = []
