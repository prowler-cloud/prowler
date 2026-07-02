from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Pipeline(BaseModel):
    """Represents an AWS Data Pipeline pipeline."""

    id: str
    name: str
    arn: str
    region: str
    definition: dict = Field(default_factory=dict)
    tags: list[dict] = Field(default_factory=list)


class DataPipeline(AWSService):
    """AWS Data Pipeline service class to list pipelines and definitions."""

    def __init__(self, provider):
        """Initialize the AWS Data Pipeline service."""
        super().__init__(__class__.__name__, provider)
        self.pipelines = {}
        self.__threading_call__(self._list_pipelines)
        if self.pipelines:
            self.__threading_call__(
                self._get_pipeline_definition, self.pipelines.values()
            )

    def _list_pipelines(self, regional_client) -> None:
        """List AWS Data Pipeline pipelines in a region."""
        logger.info("DataPipeline - Listing pipelines...")
        try:
            list_pipelines_paginator = regional_client.get_paginator("list_pipelines")
            for page in list_pipelines_paginator.paginate():
                for pipeline in page.get("pipelineIdList", []):
                    pipeline_id = pipeline.get("id")
                    pipeline_name = pipeline.get("name", pipeline_id)
                    pipeline_arn = (
                        f"arn:{self.audited_partition}:datapipeline:"
                        f"{regional_client.region}:{self.audited_account}:pipeline/{pipeline_id}"
                    )
                    if not self.audit_resources or is_resource_filtered(
                        pipeline_arn, self.audit_resources
                    ):
                        self.pipelines[pipeline_arn] = Pipeline(
                            id=pipeline_id,
                            name=pipeline_name,
                            arn=pipeline_arn,
                            region=regional_client.region,
                        )
        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_pipeline_definition(self, pipeline: Pipeline) -> None:
        """Get the full definition for an AWS Data Pipeline pipeline."""
        logger.info(f"DataPipeline - Getting definition for pipeline {pipeline.id}...")
        try:
            regional_client = self.regional_clients[pipeline.region]
            definition = regional_client.get_pipeline_definition(pipelineId=pipeline.id)
            pipeline.definition = {
                "pipelineObjects": definition.get("pipelineObjects", []),
                "parameterObjects": definition.get("parameterObjects", []),
                "parameterValues": definition.get("parameterValues", []),
            }
        except ClientError as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
