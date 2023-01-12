import datetime
import threading
from dataclasses import dataclass
from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################### Codebuild
class Codebuild:
    def __init__(self, audit_info):
        self.service = "codebuild"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.projects = []
        self.__threading_call__(self.__list_projects__)
        self.__list_builds_for_project__()

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_projects__(self, regional_client):
        logger.info("Codebuild - listing projects")
        try:
            list_projects_paginator = regional_client.get_paginator("list_projects")
            for page in list_projects_paginator.paginate():
                for project in page["projects"]:
                    self.projects.append(
                        CodebuildProject(
                            name=project,
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
class CodebuildProject:
    name: str
    region: str
    last_invoked_time: datetime
    buildspec: Optional[str]

    def __init__(self, name, region, last_invoked_time, buildspec):
        self.name = name
        self.region = region
        self.last_invoked_time = last_invoked_time
        self.buildspec = buildspec
