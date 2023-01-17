import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## APIGateway
class APIGateway:
    def __init__(self, audit_info):
        self.service = "apigateway"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audited_partition = audit_info.audited_partition
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.rest_apis = []
        self.__threading_call__(self.__get_rest_apis__)
        self.__get_authorizers__()
        self.__get_rest_api__()
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

    def __get_rest_apis__(self, regional_client):
        logger.info("APIGateway - Getting Rest APIs...")
        try:
            get_rest_apis_paginator = regional_client.get_paginator("get_rest_apis")
            for page in get_rest_apis_paginator.paginate():
                for apigw in page["items"]:
                    arn = f"arn:{self.audited_partition}:apigateway:{regional_client.region}::/apis/{apigw['id']}"
                    self.rest_apis.append(
                        RestAPI(
                            apigw["id"],
                            arn,
                            regional_client.region,
                            apigw["name"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_authorizers__(self):
        logger.info("APIGateway - Getting Rest APIs authorizer...")
        try:
            for rest_api in self.rest_apis:
                regional_client = self.regional_clients[rest_api.region]
                authorizers = regional_client.get_authorizers(restApiId=rest_api.id)[
                    "items"
                ]
                if authorizers:
                    rest_api.authorizer = True
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")

    def __get_rest_api__(self):
        logger.info("APIGateway - Describing Rest API...")
        try:
            for rest_api in self.rest_apis:
                regional_client = self.regional_clients[rest_api.region]
                rest_api_info = regional_client.get_rest_api(restApiId=rest_api.id)
                if rest_api_info["endpointConfiguration"]["types"] == ["PRIVATE"]:
                    rest_api.public_endpoint = False
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")

    def __get_stages__(self):
        logger.info("APIGateway - Getting stages for Rest APIs...")
        try:
            for rest_api in self.rest_apis:
                regional_client = self.regional_clients[rest_api.region]
                stages = regional_client.get_stages(restApiId=rest_api.id)
                for stage in stages["item"]:
                    waf = None
                    logging = False
                    client_certificate = False
                    if "webAclArn" in stage:
                        waf = stage["webAclArn"]
                    if "methodSettings" in stage:
                        if stage["methodSettings"]:
                            logging = True
                    if "clientCertificateId" in stage:
                        client_certificate = True
                    arn = f"arn:{self.audited_partition}:apigateway:{regional_client.region}::/apis/{rest_api.id}/stages/{stage['stageName']}"
                    rest_api.stages.append(
                        Stage(
                            stage["stageName"],
                            arn,
                            logging,
                            client_certificate,
                            waf,
                        )
                    )
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")


@dataclass
class Stage:
    name: str
    arn: str
    logging: bool
    client_certificate: bool
    waf: str

    def __init__(
        self,
        name,
        arn,
        logging,
        client_certificate,
        waf,
    ):
        self.name = name
        self.arn = arn
        self.logging = logging
        self.client_certificate = client_certificate
        self.waf = waf


@dataclass
class RestAPI:
    id: str
    arn: str
    region: str
    name: str
    authorizer: bool
    public_endpoint: bool
    stages: list[Stage]

    def __init__(
        self,
        id,
        arn,
        region,
        name,
    ):
        self.id = id
        self.arn = arn
        self.region = region
        self.name = name
        self.authorizer = False
        self.public_endpoint = True
        self.stages = []
