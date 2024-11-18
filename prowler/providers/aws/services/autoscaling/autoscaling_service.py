from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class AutoScaling(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.launch_configurations = {}
        self.__threading_call__(self._describe_launch_configurations)
        self.groups = []
        self.__threading_call__(self._describe_auto_scaling_groups)

    def _describe_launch_configurations(self, regional_client):
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
                        arn = configuration["LaunchConfigurationARN"]

                        self.launch_configurations[arn] = LaunchConfiguration(
                            arn=arn,
                            name=configuration["LaunchConfigurationName"],
                            user_data=configuration["UserData"],
                            image_id=configuration["ImageId"],
                            region=regional_client.region,
                            http_tokens=configuration.get("MetadataOptions", {}).get(
                                "HttpTokens", ""
                            ),
                            http_endpoint=configuration.get("MetadataOptions", {}).get(
                                "HttpEndpoint", ""
                            ),
                            public_ip=configuration.get(
                                "AssociatePublicIpAddress", False
                            ),
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_auto_scaling_groups(self, regional_client):
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
                        instance_types = []
                        az_instance_types = {}
                        for instance in group.get("Instances", []):
                            az = instance["AvailabilityZone"]
                            instance_type = instance["InstanceType"]
                            instance_types.append(instance_type)
                            if az not in az_instance_types:
                                az_instance_types[az] = set()
                            az_instance_types[az].add(instance_type)

                        self.groups.append(
                            Group(
                                arn=group.get("AutoScalingGroupARN"),
                                name=group.get("AutoScalingGroupName"),
                                region=regional_client.region,
                                availability_zones=group.get("AvailabilityZones"),
                                tags=group.get("Tags"),
                                instance_types=instance_types,
                                az_instance_types=az_instance_types,
                                capacity_rebalance=group.get(
                                    "CapacityRebalance", False
                                ),
                                launch_template=group.get("LaunchTemplate", {}),
                                mixed_instances_policy_launch_template=group.get(
                                    "MixedInstancesPolicy", {}
                                )
                                .get("LaunchTemplate", {})
                                .get("LaunchTemplateSpecification", {}),
                                health_check_type=group.get("HealthCheckType", ""),
                                load_balancers=group.get("LoadBalancerNames", []),
                                target_groups=group.get("TargetGroupARNs", []),
                                launch_configuration_name=group.get(
                                    "LaunchConfigurationName", ""
                                ),
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Global list for service namespaces needed for Describe Scalable Targets
SERVICE_NAMESPACES = ["dynamodb"]


class ApplicationAutoScaling(AWSService):
    def __init__(self, provider):
        super().__init__("application-autoscaling", provider)
        self.scalable_targets = []
        self.__threading_call__(self._describe_scalable_targets)

    def _describe_scalable_targets(self, regional_client):
        logger.info("ApplicationAutoScaling - Describing Scalable Targets...")
        try:
            describe_scalable_targets_paginator = regional_client.get_paginator(
                "describe_scalable_targets"
            )
            for service_namespace in SERVICE_NAMESPACES:
                logger.info(f"Processing ServiceNamespace: {service_namespace}")
                for page in describe_scalable_targets_paginator.paginate(
                    ServiceNamespace=service_namespace
                ):
                    for target in page.get("ScalableTargets", []):
                        if not self.audit_resources or (
                            is_resource_filtered(
                                target["ScalableTargetARN"],
                                self.audit_resources,
                            )
                        ):
                            self.scalable_targets.append(
                                ScalableTarget(
                                    arn=target.get("ScalableTargetARN", ""),
                                    resource_id=target.get("ResourceId"),
                                    service_namespace=target.get("ServiceNamespace"),
                                    scalable_dimension=target.get("ScalableDimension"),
                                    region=regional_client.region,
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
    http_tokens: str
    http_endpoint: str
    public_ip: bool


class Group(BaseModel):
    arn: str
    name: str
    region: str
    availability_zones: list
    tags: list = []
    instance_types: list = []
    az_instance_types: dict = {}
    capacity_rebalance: bool
    launch_template: dict = {}
    mixed_instances_policy_launch_template: dict = {}
    health_check_type: str
    load_balancers: list = []
    target_groups: list = []
    launch_configuration_name: str


class ScalableTarget(BaseModel):
    arn: str
    resource_id: str
    service_namespace: str
    scalable_dimension: str
    region: str
