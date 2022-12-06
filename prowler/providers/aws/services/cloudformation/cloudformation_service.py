import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## CloudFormation
class CloudFormation:
    def __init__(self, audit_info):
        self.service = "cloudformation"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.stacks = []
        self.__threading_call__(self.__describe_stacks__)
        self.__describe_stack__()

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

    def __describe_stacks__(self, regional_client):
        """Get ALL CloudFormation Stacks"""
        logger.info("CloudFormation - Describing Stacks...")
        try:
            describe_stacks_paginator = regional_client.get_paginator("describe_stacks")
            for page in describe_stacks_paginator.paginate():
                for stack in page["Stacks"]:
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
        try:
            for stack in self.stacks:
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

        except Exception as error:
            logger.error(
                f"{stack.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class Stack:
    """Stack holds a CloudFormation Stack"""

    arn: str
    """In the CloudFormation API the "Stacks[].StackId" is the ARN"""
    name: str
    """Stacks[].StackName"""
    outputs: list[str]
    """Stacks[].Outputs"""
    enable_termination_protection: bool
    """Stacks[].EnableTerminationProtection"""
    root_nested_stack: str
    """Stacks[].RootId"""
    is_nested_stack: str
    """True if the Stack is a Nested Stack"""
    region: str

    def __init__(
        self,
        arn,
        name,
        outputs,
        region,
    ):
        self.arn = arn
        self.name = name
        self.outputs = outputs
        self.enable_termination_protection = False
        self.is_nested_stack = False
        self.root_nested_stack = ""
        self.region = region
