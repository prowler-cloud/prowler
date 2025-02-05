from prowler.lib.check.models import Severity
from prowler.providers.aws.services.ec2.ec2_service import Instance
from prowler.providers.aws.services.vpc.vpc_service import VpcSubnet


def get_instance_public_status(
    vpc_subnets: dict[VpcSubnet], instance: Instance, service: str
) -> tuple:
    """
    Get the status and severity of an instance based on the service exposed to internet.
    Args:
        vpc_subnets (dict): The dictionary of VPC subnets.
        instance (Instance): The instance to check.
        service (str): The service to check.
    Returns:
        tuple: The status and severity of the instance status.
    """
    status = f"Instance {instance.id} has {service} exposed to 0.0.0.0/0 but with no public IP address."
    severity = Severity.medium

    if instance.public_ip:
        status = f"Instance {instance.id} has {service} exposed to 0.0.0.0/0 on public IP address {instance.public_ip} but it is placed in a private subnet {instance.subnet_id}."
        severity = Severity.high
        if vpc_subnets[instance.subnet_id].public:
            status = f"Instance {instance.id} has {service} exposed to 0.0.0.0/0 on public IP address {instance.public_ip} in public subnet {instance.subnet_id}."
            severity = Severity.critical

    return status, severity
