from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Branch(BaseModel):
    """Represents an AWS Amplify App Branch."""

    name: str
    arn: str
    environment_variables: dict = Field(default_factory=dict)


class App(BaseModel):
    """Represents an AWS Amplify App."""

    id: str
    name: str
    arn: str
    region: str
    environment_variables: dict = Field(default_factory=dict)
    build_spec: str = ""
    branches: list[Branch] = Field(default_factory=list)
    tags: list[dict] = Field(default_factory=list)


class Amplify(AWSService):
    """AWS Amplify service class."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.apps = {}
        self.__threading_call__(self._list_apps)
        if self.apps:
            self.__threading_call__(self._list_branches, self.apps.values())

    def _list_apps(self, regional_client) -> None:
        logger.info("Amplify - Listing apps...")
        try:
            list_apps_paginator = regional_client.get_paginator("list_apps")
            for page in list_apps_paginator.paginate():
                for app in page.get("apps", []):
                    app_id = app.get("appId")
                    app_name = app.get("name")
                    app_arn = app.get("appArn")
                    if not self.audit_resources or is_resource_filtered(
                        app_arn, self.audit_resources
                    ):
                        tags = app.get("tags", {})
                        tags_list = [tags] if tags else []
                        self.apps[app_arn] = App(
                            id=app_id,
                            name=app_name,
                            arn=app_arn,
                            region=regional_client.region,
                            environment_variables=app.get("environmentVariables", {}),
                            build_spec=app.get("buildSpec", ""),
                            tags=tags_list,
                        )
        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_branches(self, app: App) -> None:
        logger.info(f"Amplify - Listing branches for app {app.name}...")
        try:
            regional_client = self.regional_clients[app.region]
            list_branches_paginator = regional_client.get_paginator("list_branches")
            for page in list_branches_paginator.paginate(appId=app.id):
                for branch in page.get("branches", []):
                    branch_name = branch.get("branchName")
                    branch_arn = branch.get("branchArn")
                    app.branches.append(
                        Branch(
                            name=branch_name,
                            arn=branch_arn,
                            environment_variables=branch.get(
                                "environmentVariables", {}
                            ),
                        )
                    )
        except ClientError as error:
            logger.error(
                f"{app.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{app.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
