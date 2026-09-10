from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class guardduty_runtime_monitoring_enabled(Check):
    """Ensure GuardDuty unified Runtime Monitoring is enabled on every active detector.

    Runtime Monitoring covers Amazon EC2 instances, Amazon ECS on AWS Fargate tasks
    and Amazon EKS nodes and containers. Legacy EKS Runtime Monitoring covers Amazon
    EKS alone, and its AdditionalConfiguration offers no EC2 or Fargate agent
    management, so a detector running only the legacy feature has no runtime coverage
    for EC2 or Fargate workloads and cannot PASS. The two features are mutually
    exclusive at the API, so the FAIL message names the legacy case to point at
    migration rather than at first-time enablement. That exclusivity is also why the
    legacy verdict is reached before the unknown one: a legacy detector is precisely
    the one whose GetDetector response carries no RUNTIME_MONITORING entry, so testing
    for the unknown state first would report every legacy detector as undetermined.

    A detector whose own state could not be read is MANUAL rather than absent from the
    report. Detector.status is True only when GetDetector returned ENABLED and stays
    None both for a suspended detector and for a GetDetector call that failed, so those
    two cannot be told apart and neither is a definite absence of runtime coverage.
    Leaving such a detector out of the findings would leave its Region with nothing to
    read at all, and an unreported Region reads as a compliant one.

    Regions with no detector at all are left to guardduty_is_enabled entirely, which is
    also the check that owns the detector-level verdict.

    guardduty_eks_runtime_monitoring_enabled remains the EKS-scoped check.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Assess unified Runtime Monitoring on every GuardDuty detector in the account.

        Returns:
            list[Check_Report_AWS]: one report per detector that exists. PASS when
                unified Runtime Monitoring is enabled, FAIL when GuardDuty reported the
                feature disabled or reported only the legacy EKS one, and MANUAL when
                either the detector state or the feature itself was not reported and no
                legacy coverage was reported either.
        """
        findings = []
        for detector in guardduty_client.detectors:
            if not detector.enabled_in_account:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=detector)
            report.status = "FAIL"
            report.status_extended = f"GuardDuty detector {detector.id} does not have Runtime Monitoring enabled."
            if not detector.status:
                report.status = "MANUAL"
                report.status_extended = f"GuardDuty detector {detector.id} is not enabled or could not be read, so Runtime Monitoring coverage could not be determined."
            elif detector.runtime_monitoring is True:
                report.status = "PASS"
                report.status_extended = (
                    f"GuardDuty detector {detector.id} has Runtime Monitoring enabled."
                )
            elif detector.eks_runtime_monitoring:
                # Ordered ahead of the unknown branch below because a detector running the
                # legacy feature is the shape that omits RUNTIME_MONITORING entirely: the
                # two are mutually exclusive at the API. eks_runtime_monitoring is set by
                # either feature, but the PASS branch above already took the unified case,
                # so reaching here means EKS_RUNTIME_MONITORING is what enabled it. That is
                # a known absence of EC2 and Fargate coverage, not an unknown one.
                report.status_extended = f"GuardDuty detector {detector.id} only has the legacy EKS Runtime Monitoring enabled, leaving Amazon EC2 instances and Amazon ECS on Fargate tasks without runtime coverage."
            elif detector.runtime_monitoring is None:
                # GetDetector did not return RUNTIME_MONITORING at all, which is not the
                # same as returning it DISABLED: a Region that does not offer the unified
                # feature, or a features array that could not be read, would otherwise be
                # reported as a definite FAIL. No legacy coverage was reported either, so
                # nothing is known about this detector's runtime coverage.
                report.status = "MANUAL"
                report.status_extended = f"GuardDuty detector {detector.id} did not report the Runtime Monitoring feature, so runtime coverage could not be determined; verify manually."
            findings.append(report)
        return findings
