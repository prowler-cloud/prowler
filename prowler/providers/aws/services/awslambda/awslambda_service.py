import io
import json
import zipfile
from concurrent.futures import as_completed
from enum import Enum
from typing import Any, Optional

import requests
from botocore.client import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Lambda(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.functions = {}
        self.__threading_call__(self._list_functions)
        self._list_tags_for_resource()
        self.__threading_call__(self._get_policy)
        self.__threading_call__(self._get_function_url_config)
        self.__threading_call__(self._list_event_source_mappings)

    def _list_functions(self, regional_client):
        logger.info("Lambda - Listing Functions...")
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
                        vpc_config = function.get("VpcConfig", {})
                        # We must use the Lambda ARN as the dict key since we could have Lambdas in different regions with the same name
                        self.functions[lambda_arn] = Function(
                            name=lambda_name,
                            arn=lambda_arn,
                            security_groups=vpc_config.get("SecurityGroupIds", []),
                            vpc_id=vpc_config.get("VpcId"),
                            subnet_ids=set(vpc_config.get("SubnetIds", [])),
                            region=regional_client.region,
                        )
                        if "Runtime" in function:
                            self.functions[lambda_arn].runtime = function["Runtime"]
                        if "Environment" in function:
                            lambda_environment = function["Environment"].get(
                                "Variables"
                            )
                            self.functions[lambda_arn].environment = lambda_environment
                        if "KMSKeyArn" in function:
                            self.functions[lambda_arn].kms_key_arn = function[
                                "KMSKeyArn"
                            ]
                        if "Layers" in function:
                            self.functions[lambda_arn].layers = [
                                Layer(arn=layer["Arn"]) for layer in function["Layers"]
                            ]
                        dlq_arn = function.get("DeadLetterConfig", {}).get("TargetArn")
                        if dlq_arn:
                            self.functions[lambda_arn].dead_letter_config = (
                                DeadLetterConfig(target_arn=dlq_arn)
                            )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _list_event_source_mappings(self, regional_client):
        logger.info("Lambda - Listing Event Source Mappings...")
        try:
            paginator = regional_client.get_paginator("list_event_source_mappings")
            for page in paginator.paginate():
                for mapping in page.get("EventSourceMappings", []):
                    function_arn = mapping.get("FunctionArn", "")
                    # Normalise to unqualified ARN (strip :qualifier suffix if present)
                    base_arn = ":".join(function_arn.split(":")[:7])
                    if base_arn not in self.functions:
                        continue
                    self.functions[base_arn].event_source_mappings.append(
                        EventSourceMapping(
                            uuid=mapping["UUID"],
                            event_source_arn=mapping.get("EventSourceArn", ""),
                            state=mapping.get("State", ""),
                            batch_size=mapping.get("BatchSize"),
                            starting_position=mapping.get("StartingPosition"),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _get_function_code(self):
        logger.info("Lambda - Getting Function Code...")
        # Use a thread pool handle the queueing and execution of the _fetch_function_code tasks, up to max_workers tasks concurrently.
        lambda_functions_to_fetch = {
            self.thread_pool.submit(
                self._fetch_function_code, function.name, function.region
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

    def _fetch_function_code(self, function_name, function_region):
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
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise

    def _get_policy(self, regional_client):
        logger.info("Lambda - Getting Policy...")
        try:
            for function in self.functions.values():
                if function.region == regional_client.region:
                    try:
                        function_policy = regional_client.get_policy(
                            FunctionName=function.name
                        )
                        self.functions[function.arn].policy = json.loads(
                            function_policy["Policy"]
                        )
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "ResourceNotFoundException":
                            self.functions[function.arn].policy = {}

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _get_function_url_config(self, regional_client):
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

    def _list_tags_for_resource(self):
        logger.info("Lambda - List Tags...")
        try:
            for function in self.functions.values():
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


class Layer(BaseModel):
    arn: str

    @property
    def account_id(self) -> str:
        """Extract the account ID from the layer ARN."""
        parts = self.arn.split(":")
        return parts[4] if len(parts) >= 5 else ""


class DeadLetterConfig(BaseModel):
    target_arn: str


class EventSourceMapping(BaseModel):
    uuid: str
    event_source_arn: str
    state: str
    batch_size: Optional[int] = None
    starting_position: Optional[str] = None


class Function(BaseModel):
    name: str
    arn: str
    security_groups: list
    runtime: Optional[str] = None
    environment: Optional[dict] = None
    region: str
    policy: dict = {}
    code: LambdaCode = None
    url_config: URLConfig = None
    vpc_id: Optional[str] = None
    subnet_ids: Optional[set] = None
    kms_key_arn: Optional[str] = None
    layers: list[Layer] = []
    dead_letter_config: Optional[DeadLetterConfig] = None
    event_source_mappings: list[EventSourceMapping] = []
    tags: Optional[list] = []
