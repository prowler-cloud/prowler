import io
import json
import zipfile
from concurrent.futures import as_completed
from enum import Enum
from typing import Any, Optional

import requests
from botocore.client import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.check.resource_limit import get_resource_scan_limit, limit_resources
from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Lambda(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        # functions is the memoization cache for the lazy iter_functions()
        # generator. Functions are listed eagerly (a single paginated
        # list_functions call per region, no per-function cost), but expensive
        # per-function detail is hydrated on demand for selected functions.
        self.functions = {}
        self._functions_hydrated = set()
        self._event_source_mappings_listed_functions = set()
        self.function_limit = get_resource_scan_limit(
            self.audit_config, "max_lambda_functions"
        )
        self.__threading_call__(self._list_functions)

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
                        if "LastModified" in function:
                            self.functions[lambda_arn].last_modified = function[
                                "LastModified"
                            ]
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

    def _list_event_source_mappings(self, function):
        logger.info("Lambda - Listing Event Source Mappings...")
        try:
            regional_client = self.regional_clients[function.region]
            paginator = regional_client.get_paginator("list_event_source_mappings")
            for page in paginator.paginate(FunctionName=function.name):
                for mapping in page.get("EventSourceMappings", []):
                    function_arn = mapping.get("FunctionArn", "")
                    # Normalise to unqualified ARN (strip :qualifier suffix if present)
                    base_arn = ":".join(function_arn.split(":")[:7])
                    if base_arn != function.arn:
                        continue
                    function.event_source_mappings.append(
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
            for function in self.selected_functions()
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

    def _get_policy(self, function):
        logger.info("Lambda - Getting Policy...")
        try:
            regional_client = self.regional_clients[function.region]
            try:
                function_policy = regional_client.get_policy(FunctionName=function.name)
                function.policy = json.loads(function_policy["Policy"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    function.policy = {}
        except Exception as error:
            logger.error(
                f"{function.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _get_function_url_config(self, function):
        logger.info("Lambda - Getting Function URL Config...")
        try:
            regional_client = self.regional_clients[function.region]
            try:
                function_url_config = regional_client.get_function_url_config(
                    FunctionName=function.name
                )
                if "Cors" in function_url_config:
                    allow_origins = function_url_config["Cors"]["AllowOrigins"]
                else:
                    allow_origins = []
                function.url_config = URLConfig(
                    auth_type=function_url_config["AuthType"],
                    url=function_url_config["FunctionUrl"],
                    cors_config=URLConfigCORS(allow_origins=allow_origins),
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    function.url_config = None
        except Exception as error:
            logger.error(
                f"{function.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _list_tags_for_resource(self, function):
        logger.info("Lambda - List Tags...")
        try:
            regional_client = self.regional_clients[function.region]
            try:
                response = regional_client.list_tags(Resource=function.arn)["Tags"]
                function.tags = [response]
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    function.tags = []
        except Exception as error:
            logger.error(
                f"{function.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def selected_functions(self):
        return limit_resources(
            sorted(
                self.functions.values(),
                key=lambda f: f.last_modified or "",
                reverse=True,
            ),
            self.function_limit,
        )

    def iter_functions(self):
        """Yield functions lazily, hydrating expensive per-function detail on demand.

        ``list_functions`` has no server-side ordering, so newest-first is
        best-effort by ``LastModified``. Policy, URL config, tags and event
        source mappings are fetched only for the functions the consumer
        actually pulls, memoized per function ARN and shared across checks
        (checks run sequentially, so no locking needed).
        """
        for function in self.selected_functions():
            if function.arn not in self._functions_hydrated:
                if function.arn not in self._event_source_mappings_listed_functions:
                    self._list_event_source_mappings(function)
                    self._event_source_mappings_listed_functions.add(function.arn)
                self._get_policy(function)
                self._get_function_url_config(function)
                self._list_tags_for_resource(function)
                self._functions_hydrated.add(function.arn)
            yield function


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
    last_modified: Optional[str] = None
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
