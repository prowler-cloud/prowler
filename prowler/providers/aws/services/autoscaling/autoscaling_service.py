import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## AutoScaling
class AutoScaling:
    def __init__(self, audit_info):
        self.service = "autoscaling"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.launch_configurations = []
        self.__threading_call__(self.__describe_launch_configurations__)

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
                    self.launch_configurations.append(
                        LaunchConfiguration(
                            configuration["LaunchConfigurationARN"],
                            configuration["LaunchConfigurationName"],
                            configuration["UserData"],
                            configuration["ImageId"],
                            regional_client.region,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class LaunchConfiguration:
    arn: str
    name: str
    user_data: str
    image_id: int
    region: str

    def __init__(
        self,
        arn,
        name,
        user_data,
        image_id,
        region,
    ):
        self.arn = arn
        self.name = name
        self.image_id = image_id
        self.user_data = user_data
        self.region = region
