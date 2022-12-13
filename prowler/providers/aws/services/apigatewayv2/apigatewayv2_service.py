import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## ApiGatewayV2
class ApiGatewayV2:
    def __init__(self, audit_info):
        self.service = "apigatewayv2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
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
                    self.apis.append(
                        API(
                            apigw["ApiId"],
                            regional_client.region,
                            apigw["Name"],
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
                            stage["StageName"],
                            logging,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


@dataclass
class Stage:
    name: str
    logging: bool

    def __init__(
        self,
        name,
        logging,
    ):
        self.name = name
        self.logging = logging


@dataclass
class API:
    id: str
    region: str
    name: str
    authorizer: bool
    stages: list[Stage]

    def __init__(
        self,
        id,
        region,
        name,
    ):
        self.id = id
        self.region = region
        self.name = name
        self.authorizer = False
        self.stages = []
