import datetime
from dataclasses import dataclass
from typing import Optional

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################### Codebuild
class Codebuild(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.projects = []
        self.__threading_call__(self.__list_projects__)
        self.__list_builds_for_project__()

    def __list_projects__(self, regional_client):
        logger.info("Codebuild - listing projects")
        try:
            list_projects_paginator = regional_client.get_paginator("list_projects")
            for page in list_projects_paginator.paginate():
                for project in page["projects"]:
                    project_arn = f"arn:{self.audited_partition}:codebuild:{regional_client.region}:{self.audited_account}:project/{project}"
                    if not self.audit_resources or (
                        is_resource_filtered(project_arn, self.audit_resources)
                    ):
                        self.projects.append(
                            Project(
                                name=project,
                                arn=project_arn,
                                region=regional_client.region,
                                last_invoked_time=None,
                                buildspec=None,
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_builds_for_project__(self):
        logger.info("Codebuild - listing builds from projects")
        try:
            for project in self.projects:
                for region, client in self.regional_clients.items():
                    if project.region == region:
                        ids = client.list_builds_for_project(projectName=project.name)
                        if "ids" in ids:
                            if len(ids["ids"]) > 0:
                                builds = client.batch_get_builds(ids=[ids["ids"][0]])
                                if "builds" in builds:
                                    if "endTime" in builds["builds"][0]:
                                        project.last_invoked_time = builds["builds"][0][
                                            "endTime"
                                        ]

                        projects = client.batch_get_projects(names=[project.name])[
                            "projects"
                        ][0]["source"]
                        if "buildspec" in projects:
                            project.buildspec = projects["buildspec"]

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class Project:
    name: str
    arn: str
    region: str
    last_invoked_time: Optional[datetime.datetime]
    buildspec: Optional[str]
