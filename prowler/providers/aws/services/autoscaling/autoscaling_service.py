import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## AutoScaling
class AutoScaling:
    def __init__(self, audit_info):
        self.service = "autoscaling"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.launch_configurations = []
        self.__threading_call__(self.__describe_launch_configurations__)
        self.groups = []
        self.__threading_call__(self.__describe_auto_scaling_groups__)

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

    def __describe_launch_configurations__(self, regional_client):
        logger.info("AutoScaling - Describing Launch Configurations...")
        try:
            describe_launch_configurations_paginator = regional_client.get_paginator(
                "describe_launch_configurations"
            )
            for page in describe_launch_configurations_paginator.paginate():
                for configuration in page["LaunchConfigurations"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            configuration["LaunchConfigurationARN"],
                            self.audit_resources,
                        )
                    ):
                        self.launch_configurations.append(
                            LaunchConfiguration(
                                arn=configuration["LaunchConfigurationARN"],
                                name=configuration["LaunchConfigurationName"],
                                user_data=configuration["UserData"],
                                image_id=configuration["ImageId"],
                                region=regional_client.region,
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_auto_scaling_groups__(self, regional_client):
        logger.info("AutoScaling - Describing AutoScaling Groups...")
        try:
            describe_auto_scaling_groups_paginator = regional_client.get_paginator(
                "describe_auto_scaling_groups"
            )
            for page in describe_auto_scaling_groups_paginator.paginate():
                for group in page["AutoScalingGroups"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            group["AutoScalingGroupARN"],
                            self.audit_resources,
                        )
                    ):
                        self.groups.append(
                            Group(
                                arn=group.get("AutoScalingGroupARN"),
                                name=group.get("AutoScalingGroupName"),
                                region=regional_client.region,
                                availability_zones=group.get("AvailabilityZones"),
                                tags=group.get("Tags"),
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class LaunchConfiguration(BaseModel):
    arn: str
    name: str
    user_data: str
    image_id: str
    region: str


class Group(BaseModel):
    arn: str
    name: str
    region: str
    availability_zones: list
    tags: list = []
