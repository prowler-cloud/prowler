from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

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
                    pipeline_arn = f"arn:{self.audited_partition}:codepipeline:{regional_client.region}:{self.audited_account}:pipeline/{pipeline['name']}"
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

        Gets detailed information about a pipeline including its source configuration
        and tags.

        Args:
            pipeline: Pipeline object to retrieve state for.

        Raises:
            ClientError: If there is an AWS API error.
        """
        logger.info("CodePipeline - Getting pipeline state...")
        try:
            regional_client = self.regional_clients[pipeline.region]
            pipeline_info = regional_client.get_pipeline(name=pipeline.name)
            source_info = pipeline_info["pipeline"]["stages"][0]["actions"][0]
            pipeline.source = Source(
                type=source_info["actionTypeId"]["provider"],
                location=source_info["configuration"].get("FullRepositoryId", ""),
                configuration=source_info["configuration"],
            )

            # Get tags using list_tags_for_resource API
            try:
                tags_response = regional_client.list_tags_for_resource(
                    resourceArn=pipeline.arn
                )
                pipeline.tags = tags_response.get("tags", [])
            except ClientError as error:
                logger.error(
                    f"Error getting tags for pipeline {pipeline.name}: {error}"
                )
                pipeline.tags = []

        except ClientError as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Source(BaseModel):
    """Model representing a pipeline source configuration.

    Attributes:
        type: The type of source provider.
        location: The location/path of the source repository.
        configuration: Optional dictionary containing additional source configuration.
    """

    type: str
    location: str
    configuration: Optional[dict]


class Pipeline(BaseModel):
    """Model representing an AWS CodePipeline pipeline.

    Attributes:
        name: The name of the pipeline.
        arn: The ARN (Amazon Resource Name) of the pipeline.
        region: The AWS region where the pipeline exists.
        source: Optional Source object containing source configuration.
        tags: Optional list of pipeline tags.
    """

    name: str
    arn: str
    region: str
    source: Optional[Source]
    tags: Optional[list] = []
