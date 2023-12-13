import io
import json
import zipfile
from concurrent.futures import as_completed
from enum import Enum
from typing import Any, Optional

import requests
from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## Lambda
class Lambda(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.functions = {}
        self.__threading_call__(self.__list_functions__)
        self.__threading_call__(
            self.__list_tags_for_resource__, self.functions.values()
        )
        self.__threading_call__(self.__get_policy__, self.functions.values())
        self.__threading_call__(
            self.__get_function_url_config__, self.functions.values()
        )

        self.__update_progress_is_complete__()

    def __list_functions__(self, regional_client):
        try:
            list_functions_paginator = regional_client.get_paginator("list_functions")
            for page in list_functions_paginator.paginate():
                for function in page["Functions"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            function["FunctionArn"], self.audit_resources
                        )
                    ):
                        lambda_name = function["FunctionName"]
                        lambda_arn = function["FunctionArn"]
                        # We must use the Lambda ARN as the dict key since we could have Lambdas in different regions with the same name
                        self.functions[lambda_arn] = Function(
                            name=lambda_name,
                            arn=lambda_arn,
                            security_groups=function.get("VpcConfig", {}).get(
                                "SecurityGroupIds", []
                            ),
                            region=regional_client.region,
                        )
                        if "Runtime" in function:
                            self.functions[lambda_arn].runtime = function["Runtime"]
                        if "Environment" in function:
                            lambda_environment = function["Environment"].get(
                                "Variables"
                            )
                            self.functions[lambda_arn].environment = lambda_environment
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_function_code__(self):
        logger.info("Lambda - Getting Function Code...")
        # Use a thread pool handle the queueing and execution of the __fetch_function_code__ tasks, up to max_workers tasks concurrently.
        lambda_functions_to_fetch = {
            self.thread_pool.submit(
                self.__fetch_function_code__, function.name, function.region
            ): function
            for function in self.functions.values()
        }

        for fetched_lambda_code in as_completed(lambda_functions_to_fetch):
            function = lambda_functions_to_fetch[fetched_lambda_code]
            try:
                function_code = fetched_lambda_code.result()
                if function_code:
                    yield function, function_code
            except Exception as error:
                logger.error(
                    f"{function.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __fetch_function_code__(self, function_name, function_region):
        try:
            regional_client = self.regional_clients[function_region]
            function_information = regional_client.get_function(
                FunctionName=function_name
            )
            if "Location" in function_information["Code"]:
                code_location_uri = function_information["Code"]["Location"]
                raw_code_zip = requests.get(code_location_uri).content
                return LambdaCode(
                    location=code_location_uri,
                    code_zip=zipfile.ZipFile(io.BytesIO(raw_code_zip)),
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )
            raise

    def __get_policy__(self, function):
        try:
            regional_client = self.regional_clients[function.region]
            function_policy = regional_client.get_policy(FunctionName=function.name)
            self.functions[function.arn].policy = json.loads(function_policy["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.functions[function.arn].policy = {}
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_function_url_config__(self, function):
        try:
            regional_client = self.regional_clients[function.region]
            function_url_config = regional_client.get_function_url_config(
                FunctionName=function.name
            )
            if "Cors" in function_url_config:
                allow_origins = function_url_config["Cors"]["AllowOrigins"]
            else:
                allow_origins = []
            self.functions[function.arn].url_config = URLConfig(
                auth_type=function_url_config["AuthType"],
                url=function_url_config["FunctionUrl"],
                cors_config=URLConfigCORS(allow_origins=allow_origins),
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.functions[function.arn].url_config = None
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __list_tags_for_resource__(self, function):
        try:
            regional_client = self.regional_clients[function.region]
            response = regional_client.list_tags(Resource=function.arn)["Tags"]
            function.tags = [response]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                function.tags = []
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
    security_groups: list
    runtime: Optional[str]
    environment: dict = None
    region: str
    policy: dict = None
    code: LambdaCode = None
    url_config: URLConfig = None
    tags: Optional[list] = []
