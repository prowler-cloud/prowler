from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## ElasticBeanstalk
class ElasticBeanstalk(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.environments = {}
        self.__threading_call__(self._describe_environments)
        self.__threading_call__(
            self._describe_configuration_settings, self.environments.values()
        )
        self.__threading_call__(self._list_tags_for_resource)

    def _describe_environments(self, regional_client):
        logger.info("ElasticBeanstalk - Describing environments...")
        try:
            describe_environment_paginator = regional_client.get_paginator(
                "describe_environments"
            )
            for page in describe_environment_paginator.paginate():
                for environment in page["Environments"]:
                    environment_arn = environment["EnvironmentArn"]
                    if not self.audit_resources or (
                        is_resource_filtered(environment_arn, self.audit_resources)
                    ):
                        self.environments[environment_arn] = Environment(
                            id=environment["EnvironmentId"],
                            arn=environment_arn,
                            application_name=environment["ApplicationName"],
                            name=environment["EnvironmentName"],
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_configuration_settings(self, environment):
        logger.info("ElasticBeanstalk - Describing configuration settings...")
        try:
            regional_client = self.regional_clients[environment.region]
            configuration_settings = regional_client.describe_configuration_settings(
                ApplicationName=environment.application_name,
                EnvironmentName=environment.name,
            )
            option_settings = configuration_settings["ConfigurationSettings"][0].get(
                "OptionSettings", {}
            )
            for option in option_settings:
                if (
                    option["Namespace"] == "aws:elasticbeanstalk:healthreporting:system"
                    and option["OptionName"] == "SystemType"
                ):
                    environment.health_option = option.get("Value", "basic")
                elif (
                    option["Namespace"] == "aws:elasticbeanstalk:managedactions"
                    and option["OptionName"] == "ManagedActionsEnabled"
                ):
                    environment.managed_actions_option = option.get("Value", "false")
                elif (
                    option["Namespace"] == "aws:elasticbeanstalk:cloudwatch:logs"
                    and option["OptionName"] == "StreamLogs"
                ):
                    environment.cloudwatch_option = option.get("Value", "false")
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("ElasticBeanstalk -  List Tags...")
        try:
            for environment_arn, environment in self.environments.items():
                try:
                    regional_client = self.regional_clients[environment.region]
                    response = regional_client.list_tags_for_resource(
                        ResourceArn=environment_arn
                    )["TagList"]
                    environment.tags = response
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Environment(BaseModel):
    id: str
    name: str
    arn: str
    region: str
    application_name: str
    health_option: Optional[str]
    managed_actions_option: Optional[str]
    cloudwatch_option: Optional[str]
    tags: Optional[list] = []
