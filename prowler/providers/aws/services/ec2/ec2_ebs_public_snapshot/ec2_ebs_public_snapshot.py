from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_public_snapshot(Check):
    def execute(self):
        def evaluate(snapshot):
            report = Check_Report_AWS(metadata=self.metadata(), resource=snapshot)
            report.status = "PASS"
            report.status_extended = f"EBS Snapshot {snapshot.id} is not Public."
            if snapshot.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"EBS Snapshot {snapshot.id} is currently Public."
                )
            return report

        return limited_findings(
            ec2_client.iter_snapshots(determine_public=True),
            evaluate,
            get_resource_scan_limit(ec2_client.audit_config, "max_ebs_snapshots"),
        )
