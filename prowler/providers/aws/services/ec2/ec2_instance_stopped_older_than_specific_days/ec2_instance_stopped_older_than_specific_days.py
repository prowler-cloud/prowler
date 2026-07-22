import re
from datetime import datetime, timezone
from typing import Optional

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

# AWS StateTransitionReason for stopped instances, e.g.:
# "User initiated (2016-09-14 15:07:39 GMT)"
_STATE_TRANSITION_TIME_REGEX = re.compile(
    r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)"
)


def _parse_state_transition_time(
    state_transition_reason: Optional[str],
) -> Optional[datetime]:
    """Extract the stop timestamp from EC2 StateTransitionReason."""
    if not state_transition_reason:
        return None
    match = _STATE_TRANSITION_TIME_REGEX.search(state_transition_reason)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


class ec2_instance_stopped_older_than_specific_days(Check):
    """Ensure EC2 instances are not stopped longer than a configured number of days.

    Evaluates each instance's stop duration using StateTransitionReason.
    - PASS: Instance is not stopped, or has been stopped for at most the threshold.
    - FAIL: Instance has been stopped longer than max_ec2_instance_stopped_days
      (default 30).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # max_ec2_instance_stopped_days, default: 30 days
        max_ec2_instance_stopped_days = ec2_client.audit_config.get(
            "max_ec2_instance_stopped_days", 30
        )
        for instance in ec2_client.instances:
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = f"EC2 Instance {instance.id} is not stopped."
            if instance.state == "stopped":
                stop_time = _parse_state_transition_time(
                    instance.state_transition_reason
                )
                if not stop_time:
                    report.status_extended = (
                        f"EC2 Instance {instance.id} is stopped but stop time "
                        f"could not be determined."
                    )
                else:
                    time_stopped = datetime.now(timezone.utc) - stop_time
                    report.status_extended = (
                        f"EC2 Instance {instance.id} has not been stopped longer "
                        f"than {max_ec2_instance_stopped_days} days "
                        f"({time_stopped.days} days)."
                    )
                    if time_stopped.days > max_ec2_instance_stopped_days:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"EC2 Instance {instance.id} has been stopped longer "
                            f"than {max_ec2_instance_stopped_days} days "
                            f"({time_stopped.days} days)."
                        )

            findings.append(report)

        return findings
