import threading
from re import sub

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ ECS
class ECS:
    def __init__(self, audit_info):
        self.service = "ecs"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.task_definitions = []
        self.__threading_call__(self.__list_task_definitions__)
        self.__describe_task_definition__()

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

    def __list_task_definitions__(self, regional_client):
        logger.info("ECS - Listing Task Definitions...")
        try:

            list_ecs_paginator = regional_client.get_paginator("list_task_definitions")
            for page in list_ecs_paginator.paginate():
                for task_definition in page["taskDefinitionArns"]:
                    self.task_definitions.append(
                        TaskDefinition(
                            # we want the family name without the revision
                            name=sub(":.*", "", task_definition.split("/")[1]),
                            arn=task_definition,
                            region=regional_client.region,
                            environment_variables=[],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_task_definition__(self):
        logger.info("ECS - Describing Task Definitions...")
        try:
            for task_definition in self.task_definitions:
                client = self.regional_clients[task_definition.region]
                container_definitions = client.describe_task_definition(
                    taskDefinition=task_definition.arn
                )["taskDefinition"]["containerDefinitions"]
                for container in container_definitions:
                    if "environment" in container:
                        for env_var in container["environment"]:
                            task_definition.environment_variables.append(
                                ContainerEnvVariable(
                                    name=env_var["name"], value=env_var["value"]
                                )
                            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ContainerEnvVariable(BaseModel):
    name: str
    value: str


class TaskDefinition(BaseModel):
    name: str
    arn: str
    region: str
    environment_variables: list[ContainerEnvVariable]
