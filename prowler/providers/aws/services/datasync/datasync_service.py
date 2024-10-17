from typing import Dict, List, Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class DataSync(AWSService):
    """AWS DataSync service class to list tasks, describe them, and list their tags."""

    def __init__(self, provider):
        """Initialize the DataSync service.

        Args:
            provider: The AWS provider instance.
        """

        super().__init__(__class__.__name__, provider)
        self.tasks = {}
        self.__threading_call__(self._list_tasks)
        self.__threading_call__(self._describe_tasks, self.tasks.values())
        self.__threading_call__(self._list_task_tags, self.tasks.values())

    def _list_tasks(self, regional_client):
        """List DataSync tasks in the given region.

        Args:
            regional_client: The regional AWS client.
        """

        logger.info("DataSync - Listing tasks...")
        try:
            list_tasks_paginator = regional_client.get_paginator("list_tasks")
            for page in list_tasks_paginator.paginate():
                for task in page.get("Tasks", []):
                    task_arn = task["TaskArn"]
                    task_id = task_arn.split("/")[-1]
                    if not self.audit_resources or (
                        is_resource_filtered(task_arn, self.audit_resources)
                    ):
                        self.tasks[task_arn] = DataSyncTask(
                            id=task_id,
                            arn=task_arn,
                            name=task.get("Name"),
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_tasks(self, task):
        """Describe each DataSync task and update task details."""

        logger.info("DataSync - Describing tasks...")
        try:
            regional_client = self.regional_clients[task.region]
            response = regional_client.describe_task(TaskArn=task.arn)
            task.status = response.get("Status")
            task.options = response.get("Options")
            task.source_location_arn = response.get("SourceLocationArn")
            task.destination_location_arn = response.get("DestinationLocationArn")
            task.excludes = response.get("Excludes")
            task.schedule = response.get("Schedule")
            task.cloudwatch_log_group_arn = response.get("CloudWatchLogGroupArn")
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_task_tags(self, task):
        """List tags for each DataSync task."""

        logger.info("DataSync - Listing task tags...")
        try:
            regional_client = self.regional_clients[task.region]
            response = regional_client.list_tags_for_resource(ResourceArn=task.arn)
            task.tags = response.get("Tags", [])
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class DataSyncTask(BaseModel):
    id: str
    name: Optional[str] = None
    arn: str
    region: str
    status: Optional[str] = None
    options: Optional[Dict] = None
    source_location_arn: Optional[str] = None
    destination_location_arn: Optional[str] = None
    excludes: Optional[List] = None
    schedule: Optional[Dict] = None
    cloudwatch_log_group_arn: Optional[str] = None
    tags: List[Dict] = Field(default_factory=list)
