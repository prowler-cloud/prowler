import datetime
from typing import Optional

from pydantic import BaseModel

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
        self.__threading_call__(self.__list_builds_for_project__)
        self.__threading_call__(self.__batch_get_builds__)
        self.__threading_call__(self.__batch_get_projects__)

    def __list_projects__(self, regional_client):
        logger.info("Codebuild - Listing projects...")
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
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_builds_for_project__(self, regional_client):
        logger.info("Codebuild - Listing builds...")
        try:
            for project in self.projects:
                if project.region == regional_client.region:
                    try:
                        project.build_ids = regional_client.list_builds_for_project(
                            projectName=project.name
                        ).get("ids", [])
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __batch_get_builds__(self, regional_client):
        logger.info("Codebuild - Getting builds...")
        try:
            for project in self.projects:
                if project.region == regional_client.region and project.build_ids:
                    try:
                        builds = regional_client.batch_get_builds(
                            ids=[project.build_ids[0]]
                        ).get("builds", [])
                        if builds:
                            if "endTime" in builds[0]:
                                project.last_invoked_time = builds[0]["endTime"]
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __batch_get_projects__(self, regional_client):
        logger.info("Codebuild - Getting projects...")
        try:
            for project in self.projects:
                if project.region == regional_client.region:
                    try:
                        projects = regional_client.batch_get_projects(
                            names=[project.name]
                        )["projects"][0]["source"]
                        if "buildspec" in projects:
                            project.buildspec = projects["buildspec"]
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Project(BaseModel):
    name: str
    arn: str
    region: str
    build_ids: list = []
    last_invoked_time: Optional[datetime.datetime]
    buildspec: Optional[str]
