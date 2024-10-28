from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## APIGateway
class APIGateway(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.rest_apis = []
        self.__threading_call__(self._get_rest_apis)
        self._get_authorizers()
        self._get_rest_api()
        self._get_stages()
        self._get_resources()

    def _get_rest_apis(self, regional_client):
        logger.info("APIGateway - Getting Rest APIs...")
        try:
            get_rest_apis_paginator = regional_client.get_paginator("get_rest_apis")
            for page in get_rest_apis_paginator.paginate():
                for apigw in page["items"]:
                    arn = f"arn:{self.audited_partition}:apigateway:{regional_client.region}::/restapis/{apigw['id']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.rest_apis.append(
                            RestAPI(
                                id=apigw["id"],
                                arn=arn,
                                region=regional_client.region,
                                name=apigw.get("name", ""),
                                tags=[apigw.get("tags")],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_authorizers(self):
        logger.info("APIGateway - Getting Rest APIs authorizer...")
        try:
            for rest_api in self.rest_apis:
                try:
                    regional_client = self.regional_clients[rest_api.region]
                    authorizers = regional_client.get_authorizers(
                        restApiId=rest_api.id
                    )["items"]
                    if authorizers:
                        rest_api.authorizer = True

                except ClientError as error:
                    if error.response["Error"]["Code"] == "NotFoundException":
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
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_rest_api(self):
        logger.info("APIGateway - Describing Rest API...")
        try:
            for rest_api in self.rest_apis:
                try:
                    regional_client = self.regional_clients[rest_api.region]
                    rest_api_info = regional_client.get_rest_api(restApiId=rest_api.id)
                    if rest_api_info["endpointConfiguration"]["types"] == ["PRIVATE"]:
                        rest_api.public_endpoint = False
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NotFoundException":
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
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_stages(self):
        logger.info("APIGateway - Getting stages for Rest APIs...")
        try:
            for rest_api in self.rest_apis:
                try:
                    regional_client = self.regional_clients[rest_api.region]
                    stages = regional_client.get_stages(restApiId=rest_api.id)
                    for stage in stages["item"]:
                        waf = None
                        logging = False
                        client_certificate = False
                        tracing_enabled = False
                        if "tracingEnabled" in stage:
                            if stage["tracingEnabled"]:
                                tracing_enabled = True
                        cache_enabled = False
                        cache_data_encrypted = False
                        if "webAclArn" in stage:
                            waf = stage["webAclArn"]
                        if "methodSettings" in stage:
                            for settings in stage["methodSettings"].values():
                                if settings.get("loggingLevel"):
                                    logging = True
                                if settings.get("cachingEnabled"):
                                    cache_enabled = True
                                    if settings.get("cacheDataEncrypted"):
                                        cache_data_encrypted = True
                        if "clientCertificateId" in stage:
                            client_certificate = True
                        arn = f"arn:{self.audited_partition}:apigateway:{regional_client.region}::/restapis/{rest_api.id}/stages/{stage['stageName']}"
                        rest_api.stages.append(
                            Stage(
                                name=stage["stageName"],
                                arn=arn,
                                logging=logging,
                                client_certificate=client_certificate,
                                waf=waf,
                                tags=[stage.get("tags")],
                                tracing_enabled=tracing_enabled,
                                cache_enabled=cache_enabled,
                                cache_data_encrypted=cache_data_encrypted,
                            )
                        )
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NotFoundException":
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
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_resources(self):
        logger.info("APIGateway - Getting API resources...")
        try:
            for rest_api in self.rest_apis:
                try:
                    regional_client = self.regional_clients[rest_api.region]
                    get_resources_paginator = regional_client.get_paginator(
                        "get_resources"
                    )
                    for page in get_resources_paginator.paginate(restApiId=rest_api.id):
                        for resource in page["items"]:
                            id = resource["id"]
                            resource_methods = []
                            methods_auth = {}
                            for resource_method in resource.get(
                                "resourceMethods", {}
                            ).keys():
                                resource_methods.append(resource_method)

                            for resource_method in resource_methods:
                                if resource_method != "OPTIONS":
                                    method_config = regional_client.get_method(
                                        restApiId=rest_api.id,
                                        resourceId=id,
                                        httpMethod=resource_method,
                                    )
                                    auth_type = method_config["authorizationType"]
                                    methods_auth.update({resource_method: auth_type})

                            rest_api.resources.append(
                                PathResourceMethods(
                                    path=resource["path"], resource_methods=methods_auth
                                )
                            )
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NotFoundException":
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

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Stage(BaseModel):
    name: str
    arn: str
    logging: bool
    client_certificate: bool
    waf: Optional[str]
    tags: Optional[list] = []
    tracing_enabled: Optional[bool]
    cache_enabled: Optional[bool]
    cache_data_encrypted: Optional[bool]


class PathResourceMethods(BaseModel):
    path: str
    resource_methods: dict


class RestAPI(BaseModel):
    id: str
    arn: str
    region: str
    name: str
    authorizer: bool = False
    public_endpoint: bool = True
    stages: list[Stage] = []
    tags: Optional[list] = []
    resources: list[PathResourceMethods] = []
