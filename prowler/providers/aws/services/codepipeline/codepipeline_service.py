from typing import List, Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


class CodePipeline(AWSService):
    """AWS CodePipeline service class for managing pipeline resources.

    This class handles interactions with AWS CodePipeline service, including
    listing pipelines and retrieving their states. It manages pipeline resources
    and their associated metadata.

    Attributes:
        pipelines: Dictionary mapping pipeline ARNs to Pipeline objects.
    """

    def __init__(self, provider):
        """Initializes the CodePipeline service class.

        Args:
            provider: AWS provider instance for making API calls.
        """
        super().__init__(__class__.__name__, provider)
        self.pipelines = {}
        self.__threading_call__(self._list_pipelines)
        if self.pipelines:
            self.__threading_call__(self._get_pipeline_state, self.pipelines.values())
            self.__threading_call__(
                self._list_tags_for_resource, self.pipelines.values()
            )

    def _list_pipelines(self, regional_client):
        """Lists all CodePipeline pipelines in the specified region.

        Retrieves all pipelines using pagination and creates Pipeline objects
        for each pipeline found.

        Args:
            regional_client: AWS regional client for CodePipeline service.

        Raises:
            ClientError: If there is an AWS API error.
        """
        logger.info("CodePipeline - Listing pipelines...")
        try:
            list_pipelines_paginator = regional_client.get_paginator("list_pipelines")
            for page in list_pipelines_paginator.paginate():
                for pipeline in page["pipelines"]:
                    pipeline_arn = f"arn:{self.audited_partition}:codepipeline:{regional_client.region}:{self.audited_account}:{pipeline['name']}"
                    if self.pipelines is None:
                        self.pipelines = {}
                    self.pipelines[pipeline_arn] = Pipeline(
                        name=pipeline["name"],
                        arn=pipeline_arn,
                        region=regional_client.region,
                    )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.pipelines:
                    self.pipelines = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_pipeline_state(self, pipeline):
        """Retrieves the current state of a pipeline.

        Gets detailed information about a pipeline including its source configuration.

        Args:
            pipeline: Pipeline object to retrieve state for.

        Raises:
            ClientError: If there is an AWS API error.
        """
        logger.info("CodePipeline - Getting pipeline state...")
        try:
            regional_client = self.regional_clients[pipeline.region]
            pipeline_info = regional_client.get_pipeline(name=pipeline.name)
            all_stages = pipeline_info["pipeline"]["stages"]

            # Capture all stages and their action configurations for secret scanning
            for stage in all_stages:
                stage_obj = PipelineStage(name=stage["name"])
                for action in stage.get("actions", []):
                    stage_obj.actions.append(
                        PipelineAction(
                            name=action["name"],
                            configuration=action.get("configuration"),
                        )
                    )
                pipeline.stages.append(stage_obj)

            # Capture source info from the first stage/action (existing behaviour)
            source_info = all_stages[0]["actions"][0]
            repository_id = source_info["configuration"].get("FullRepositoryId", "")
            pipeline.source = Source(
                type=source_info["actionTypeId"]["provider"],
                repository_id=repository_id,
                configuration=source_info["configuration"],
            )

        except ClientError as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, resource):
        """Lists tags for a given resource.

        Args:
            resource: Resource object to retrieve tags for.
        """
        logger.info("CodePipeline - Listing Tags...")
        try:
            tags_response = self.regional_clients[
                resource.region
            ].list_tags_for_resource(resourceArn=resource.arn)
            resource.tags = tags_response.get("tags", [])
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Source(BaseModel):
    """Model representing a pipeline source configuration.

    Attributes:
        type: The type of source provider.
        repository_id: The repository identifier.
        configuration: Optional dictionary containing additional source configuration.
    """

    type: str
    repository_id: str
    configuration: Optional[dict]


class PipelineAction(BaseModel):
    """Model representing a single action within a pipeline stage.

    Attributes:
        name: The name of the action.
        configuration: Optional dictionary of action configuration key/value pairs.
    """

    name: str
    configuration: Optional[dict] = None


class PipelineStage(BaseModel):
    """Model representing a stage within a CodePipeline pipeline.

    Attributes:
        name: The name of the stage.
        actions: List of actions defined in this stage.
    """

    name: str
    actions: List[PipelineAction] = Field(default_factory=list)


class Pipeline(BaseModel):
    """Model representing an AWS CodePipeline pipeline.

    Attributes:
        name: The name of the pipeline.
        arn: The ARN (Amazon Resource Name) of the pipeline.
        region: The AWS region where the pipeline exists.
        source: Optional Source object containing source configuration.
        stages: List of all pipeline stages with their action configurations.
        tags: Optional list of pipeline tags.
    """

    name: str
    arn: str
    region: str
    source: Optional[Source] = None
    stages: List[PipelineStage] = Field(default_factory=list)
    tags: Optional[list] = []
