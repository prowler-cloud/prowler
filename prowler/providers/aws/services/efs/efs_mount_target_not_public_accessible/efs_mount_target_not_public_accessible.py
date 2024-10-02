from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class efs_mount_target_not_public_accessible(Check):
    def execute(self):
        findings = []
        for fs in efs_client.filesystems.values():
            if fs.mount_targets:
                report = Check_Report_AWS(self.metadata())
                report.region = fs.region
                report.resource_id = fs.id
                report.resource_arn = fs.arn
                report.resource_tags = fs.tags
                report.status = "PASS"
                report.status_extended = f"EFS {fs.id} does not have any mount target associated with a public subnet."
                mount_targets = []
                for mt in fs.mount_targets:
                    if vpc_client.vpc_subnets[mt.subnet_id].public:
                        mount_targets.append(mt)
                if mount_targets:
                    report.status = "FAIL"
                    report.status_extended = f"EFS {fs.id} has mount targets associated with public subnets: {', '.join([mt.id for mt in mount_targets])}"

                findings.append(report)
        return findings
