from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## ApiGatewayV2
class ApiGatewayV2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.apis = []
        self.__threading_call__(self.__get_apis__)
        self.__get_authorizers__()
        self.__get_stages__()

    def __get_apis__(self, regional_client):
        logger.info("APIGatewayv2 - Getting APIs...")
        try:
            get_apis_paginator = regional_client.get_paginator("get_apis")
            for page in get_apis_paginator.paginate():
                for apigw in page["Items"]:
                    arn = f"arn:{self.audited_partition}:apigateway:{regional_client.region}::apis/{apigw['ApiId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.apis.append(
                            API(
                                arn=arn,
                                id=apigw["ApiId"],
                                region=regional_client.region,
                                name=apigw["Name"],
                                tags=[apigw.get("Tags")],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_authorizers__(self):
        logger.info("APIGatewayv2 - Getting APIs authorizer...")
        try:
            for api in self.apis:
                regional_client = self.regional_clients[api.region]
                authorizers = regional_client.get_authorizers(ApiId=api.id)["Items"]
                if authorizers:
                    api.authorizer = True
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __get_stages__(self):
        logger.info("APIGatewayv2 - Getting stages for APIs...")
        try:
            for api in self.apis:
                regional_client = self.regional_clients[api.region]
                stages = regional_client.get_stages(ApiId=api.id)
                for stage in stages["Items"]:
                    logging = False
                    if "AccessLogSettings" in stage:
                        logging = True
                    api.stages.append(
                        Stage(
                            name=stage["StageName"],
                            logging=logging,
                            tags=[stage.get("Tags")],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class Stage(BaseModel):
    name: str
    logging: bool
    tags: Optional[list] = []


class API(BaseModel):
    arn: str
    id: str
    region: str
    name: str
    authorizer: bool = False
    stages: list[Stage] = []
    tags: Optional[list] = []
