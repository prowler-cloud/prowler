from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.elb.elb_client import elb_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports import (
    ec2_securitygroup_allow_ingress_from_internet_to_all_ports,
)


class ec2_instance_not_directly_publicly_accessible_via_elb(Check):
    def execute(self):
        findings = []

        public_instances = {}
        public = False
        for lb in elb_client.loadbalancers:
            if lb.public:
                for myinstance in lb.instances_ids:
                    for instance in ec2_client.instances:
                        if instance.id == myinstance:
                            for security_group in ec2_client.security_groups:
                                if security_group.id in instance.security_groups:
                                    # Check if ignoring flag is set and if the VPC and the SG is in use
                                    if ec2_client.provider.scan_unused_services or (
                                        security_group.vpc_id in vpc_client.vpcs
                                        and vpc_client.vpcs[
                                            security_group.vpc_id
                                        ].in_use
                                        and len(security_group.network_interfaces) > 0
                                    ):
                                        for (
                                            ingress_rule
                                        ) in security_group.ingress_rules:
                                            if check_security_group(
                                                ingress_rule, "-1", any_address=True
                                            ):
                                                ec2_client.set_failed_check(
                                                    self.__class__.__name__,
                                                    security_group.arn,
                                                )
                                                public = True
                                                break

                                        if not public:
                                            # only proceed if check "..._to_all_ports" did not run or did not FAIL to avoid to report open ports twice
                                            if not ec2_client.is_failed_check(
                                                ec2_securitygroup_allow_ingress_from_internet_to_all_ports.__name__,
                                                security_group.arn,
                                            ):
                                                # Loop through every security group's ingress rule and check it
                                                for (
                                                    ingress_rule
                                                ) in security_group.ingress_rules:
                                                    if check_security_group(
                                                        ingress_rule,
                                                        "-1",
                                                        ports=None,
                                                        any_address=True,
                                                    ):
                                                        public = True

                                            else:
                                                public = True
                                if public:
                                    break

                    public_instances[myinstance] = lb

        for instance in ec2_client.instances:
            if instance.state != "terminated":
                report = Check_Report_AWS(self.metadata())
                report.region = instance.region
                report.resource_id = instance.id
                report.resource_arn = instance.arn
                report.resource_tags = instance.tags
                report.status = "PASS"
                report.status_extended = f"EC2 Instance {instance.id} is not publicly accesible through an Internet facing Classic Load Balancer."

                if instance.id in public_instances:
                    report.status = "FAIL"
                    report.status_extended = f"EC2 Instance {instance.id} is publicly accesible through an Internet facing Classic Load Balancer through load balancer {public_instances[instance.id].dns}."
                findings.append(report)

        return findings
