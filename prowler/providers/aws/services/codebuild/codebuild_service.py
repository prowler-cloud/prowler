import datetime
from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Codebuild(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.projects = {}
        self.__threading_call__(self._list_projects)
        self.__threading_call__(self._list_builds_for_project, self.projects.values())
        self.__threading_call__(self._batch_get_builds, self.projects.values())
        self.__threading_call__(self._batch_get_projects, self.projects.values())
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

    def _list_builds_for_project(self, project):
        logger.info("Codebuild - Listing builds...")
        try:
            regional_client = self.regional_clients[project.region]
            build_ids = regional_client.list_builds_for_project(
                projectName=project.name
            ).get("ids", [])
            if len(build_ids) > 0:
                project.last_build = Build(id=build_ids[0])
        except Exception as error:
            logger.error(
                f"{project.region}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _batch_get_builds(self, project):
        logger.info("Codebuild - Getting builds...")
        try:
            if project.last_build and project.last_build.id:
                regional_client = self.regional_clients[project.region]
                builds_by_id = regional_client.batch_get_builds(
                    ids=[project.last_build.id]
                ).get("builds", [])
                if len(builds_by_id) > 0:
                    project.last_invoked_time = builds_by_id[0].get("endTime")
        except Exception as error:
            logger.error(
                f"{regional_client.region}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _batch_get_projects(self, project):
        logger.info("Codebuild - Getting projects...")
        try:
            regional_client = self.regional_clients[project.region]
            project_info = regional_client.batch_get_projects(names=[project.name])[
                "projects"
            ][0]
            project.buildspec = project_info["source"].get("buildspec")
            if project_info["source"]["type"] != "NO_SOURCE":
                project.source = Source(
                    type=project_info["source"]["type"],
                    location=project_info["source"]["location"],
                )
            project.secondary_sources = []
            for secondary_source in project_info.get("secondarySources", []):
                source_obj = Source(
                    type=secondary_source["type"], location=secondary_source["location"]
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


class Project(BaseModel):
    name: str
    arn: str
    region: str
    last_build: Optional[Build]
    last_invoked_time: Optional[datetime.datetime]
    buildspec: Optional[str]
    source: Optional[Source]
    secondary_sources: Optional[list[Source]] = []
    environment_variables: Optional[List[EnvironmentVariable]]
    s3_logs: Optional[s3Logs]
    cloudwatch_logs: Optional[CloudWatchLogs]
    tags: Optional[list]


class ExportConfig(BaseModel):
    type: str
    bucket_location: str
    encryption_key: str
    encrypted: bool


class ReportGroup(BaseModel):
    arn: str
    name: str
    region: str
    status: Optional[str]
    export_config: Optional[ExportConfig]
    tags: Optional[list]
