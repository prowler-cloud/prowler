from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


class CodePipeline(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.pipelines = {}
        self.__threading_call__(self._list_pipelines)
        if self.pipelines:
            self.__threading_call__(self._get_pipeline_state, self.pipelines.values())

    def _list_pipelines(self, regional_client):
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
            pipeline.tags = pipeline_info.get("tags", [])
        except ClientError as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{pipeline.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Source(BaseModel):
    type: str
    location: str
    configuration: Optional[dict]


class Pipeline(BaseModel):
    name: str
    arn: str
    region: str
    source: Optional[Source]
    tags: Optional[list] = []
