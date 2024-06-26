from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## CloudFormation
class CloudFormation(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.stacks = []
        self.__threading_call__(self.__describe_stacks__)
        self.__describe_stack__()

    def __describe_stacks__(self, regional_client):
        """Get ALL CloudFormation Stacks"""
        logger.info("CloudFormation - Describing Stacks...")
        try:
            describe_stacks_paginator = regional_client.get_paginator("describe_stacks")
            for page in describe_stacks_paginator.paginate():
                for stack in page["Stacks"]:
                    if not self.audit_resources or (
                        is_resource_filtered(stack["StackId"], self.audit_resources)
                    ):
                        outputs = []
                        if "Outputs" in stack:
                            for output in stack["Outputs"]:
                                outputs.append(
                                    f"{output['OutputKey']}:{output['OutputValue']}"
                                )
                        self.stacks.append(
                            Stack(
                                arn=stack["StackId"],
                                name=stack["StackName"],
                                tags=stack.get("Tags"),
                                outputs=outputs,
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_stack__(self):
        """Get Details for a CloudFormation Stack"""
        logger.info("CloudFormation - Describing Stack to get specific details...")
        for stack in self.stacks:
            try:
                stack_details = self.regional_clients[stack.region].describe_stacks(
                    StackName=stack.name
                )
                # Termination Protection
                stack.enable_termination_protection = stack_details["Stacks"][0][
                    "EnableTerminationProtection"
                ]
                # Nested Stack
                if "RootId" in stack_details["Stacks"][0]:
                    stack.root_nested_stack = stack_details["Stacks"][0]["RootId"]
                stack.is_nested_stack = True if stack.root_nested_stack != "" else False

            except ClientError as error:
                if error.response["Error"]["Code"] == "ValidationError":
                    logger.warning(
                        f"{stack.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
            except Exception as error:
                logger.error(
                    f"{stack.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Stack(BaseModel):
    """Stack holds a CloudFormation Stack"""

    arn: str
    """In the CloudFormation API the "Stacks[].StackId" is the ARN"""
    name: str
    """Stacks[].StackName"""
    outputs: list[str]
    """Stacks[].Outputs"""
    enable_termination_protection: bool = False
    """Stacks[].EnableTerminationProtection"""
    root_nested_stack: str = ""
    """Stacks[].RootId"""
    is_nested_stack: bool = False
    """True if the Stack is a Nested Stack"""
    tags: Optional[list] = []
    region: str
