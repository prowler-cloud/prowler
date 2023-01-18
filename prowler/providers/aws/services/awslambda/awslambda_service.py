import io
import json
import threading
import zipfile
from enum import Enum
from typing import Any

import requests
from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## Lambda
class Lambda:
    def __init__(self, audit_info):
        self.service = "lambda"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.functions = {}
        self.__threading_call__(self.__list_functions__)
        self.__threading_call__(self.__get_function__)
        self.__threading_call__(self.__get_policy__)
        self.__threading_call__(self.__get_function_url_config__)

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

    def __list_functions__(self, regional_client):
        logger.info("Lambda - Listing Functions...")
        try:
            list_functions_paginator = regional_client.get_paginator("list_functions")
            for page in list_functions_paginator.paginate():
                for function in page["Functions"]:
                    lambda_name = function["FunctionName"]
                    lambda_arn = function["FunctionArn"]
                    lambda_runtime = function["Runtime"]
                    self.functions[lambda_name] = Function(
                        name=lambda_name,
                        arn=lambda_arn,
                        runtime=lambda_runtime,
                        region=regional_client.region,
                    )
                    if "Environment" in function:
                        lambda_environment = function["Environment"]["Variables"]
                        self.functions[lambda_name].environment = lambda_environment

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_function__(self, regional_client):
        logger.info("Lambda - Getting Function...")
        try:
            for function in self.functions.values():
                if function.region == regional_client.region:
                    function_information = regional_client.get_function(
                        FunctionName=function.name
                    )
                    code_location_uri = function_information["Code"]["Location"]
                    raw_code_zip = requests.get(code_location_uri).content
                    self.functions[function.name].code = LambdaCode(
                        location=code_location_uri,
                        code_zip=zipfile.ZipFile(io.BytesIO(raw_code_zip)),
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_policy__(self, regional_client):
        logger.info("Lambda - Getting Policy...")
        try:
            for function in self.functions.values():
                if function.region == regional_client.region:
                    try:
                        function_policy = regional_client.get_policy(
                            FunctionName=function.name
                        )
                        self.functions[function.name].policy = json.loads(
                            function_policy["Policy"]
                        )
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "ResourceNotFoundException":
                            self.functions[function.name].policy = {}

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_function_url_config__(self, regional_client):
        logger.info("Lambda - Getting Function URL Config...")
        try:
            for function in self.functions.values():
                if function.region == regional_client.region:
                    try:
                        function_url_config = regional_client.get_function_url_config(
                            FunctionName=function.name
                        )
                        if "Cors" in function_url_config:
                            allow_origins = function_url_config["Cors"]["AllowOrigins"]
                        else:
                            allow_origins = []
                        self.functions[function.name].url_config = URLConfig(
                            auth_type=function_url_config["AuthType"],
                            url=function_url_config["FunctionUrl"],
                            cors_config=URLConfigCORS(allow_origins=allow_origins),
                        )
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "ResourceNotFoundException":
                            self.functions[function.name].url_config = None

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class LambdaCode(BaseModel):
    location: str
    code_zip: Any


class AuthType(Enum):
    NONE = "NONE"
    AWS_IAM = "AWS_IAM"


class URLConfigCORS(BaseModel):
    allow_origins: list[str]


class URLConfig(BaseModel):
    auth_type: AuthType
    url: str
    cors_config: URLConfigCORS


class Function(BaseModel):
    name: str
    arn: str
    runtime: str
    environment: dict = None
    region: str
    policy: dict = None
    code: LambdaCode = None
    url_config: URLConfig = None
