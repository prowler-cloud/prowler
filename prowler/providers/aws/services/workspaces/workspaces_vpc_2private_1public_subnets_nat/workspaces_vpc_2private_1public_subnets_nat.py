from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client
from prowler.providers.aws.services.workspaces.workspaces_client import (
    workspaces_client,
)


class workspaces_vpc_2private_1public_subnets_nat(Check):
    def execute(self):
        findings = []
        for workspace in workspaces_client.workspaces:
            report = Check_Report_AWS(self.metadata())
            report.region = workspace.region
            report.resource_id = workspace.id
            report.resource_arn = workspace.arn
            report.resource_tags = workspace.tags
            report.status = "PASS"
            report.status_extended = f"Workspace {workspace.id} is in a private subnet within a VPC which has 1 public subnet 2 private subnets with a NAT Gateway attached."
            vpc_object = None
            is_in_private_subnet = False
            if workspace.subnet_id:
                if vpc_client.vpcs[vpc_client.vpc_subnets[workspace.subnet_id].vpc_id]:
                    vpc_object = vpc_client.vpcs[
                        vpc_client.vpc_subnets[workspace.subnet_id].vpc_id
                    ]
                if vpc_client.vpc_subnets[workspace.subnet_id]:
                    if not vpc_client.vpc_subnets[workspace.subnet_id].public:
                        is_in_private_subnet = True
            public_subnets = 0
            private_subnets = 0
            nat_gateway = False
            if vpc_object:
                for vpc_subnet in vpc_object.subnets:
                    if vpc_subnet.public:
                        public_subnets += 1
                    if not vpc_subnet.public:
                        private_subnets += 1
                        if vpc_subnet.nat_gateway:
                            nat_gateway = True
                        # Check NAT Gateway here
            if (
                public_subnets < 1
                or private_subnets < 2
                or not nat_gateway
                or not is_in_private_subnet
            ):
                report.status = "FAIL"
                report.status_extended = f"Workspace {workspace.id} is not in a private subnet or its VPC does not have 1 public subnet and 2 private subnets with a NAT Gateway attached."

            findings.append(report)
        return findings
