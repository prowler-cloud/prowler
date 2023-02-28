import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## ApiGatewayV2
class ApiGatewayV2:
    def __init__(self, audit_info):
        self.service = "apigatewayv2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.apis = []
        self.__threading_call__(self.__get_apis__)
        self.__get_authorizers__()
        self.__get_stages__()

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

    def __get_apis__(self, regional_client):
        logger.info("APIGatewayv2 - Getting APIs...")
        try:
            get_rest_apis_paginator = regional_client.get_paginator("get_apis")
            for page in get_rest_apis_paginator.paginate():
                for apigw in page["Items"]:
                    if not self.audit_resources or (
                        is_resource_filtered(apigw["ApiId"], self.audit_resources)
                    ):
                        self.apis.append(
                            API(
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
    tags: list = []


class API(BaseModel):
    id: str
    region: str
    name: str
    authorizer: bool = False
    stages: list[Stage] = []
    tags: list = []
