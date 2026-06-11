from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.config.config_client import config_client
from prowler.providers.aws.services.config.config_service import Aggregator


class config_delegated_admin_and_org_aggregator_all_regions(Check):
    """Ensure AWS Config has a delegated admin and an org aggregator covering all regions.

    This check verifies that:
    1. A delegated administrator is registered for the config.amazonaws.com
       service principal via AWS Organizations.
    2. At least one AWS Config Configuration Aggregator exists with an
       OrganizationAggregationSource that covers all AWS regions
       (AllAwsRegions=true).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check. One finding per
            aggregator-region, or a single synthetic FAIL when no aggregators
            exist in any region.
        """
        findings = []

        has_delegated_admin = (
            bool(config_client.delegated_administrators)
            and not config_client.delegated_administrators_lookup_failed
        )
        delegated_admin_unknown = config_client.delegated_administrators_lookup_failed

        # No aggregators in any region: emit one synthetic FAIL anchored to the
        # audited account in the default region.
        if not config_client.aggregators:
            synthetic = Aggregator(
                name="unknown",
                arn=config_client.get_unknown_arn(
                    region=config_client.region,
                    resource_type="config-aggregator",
                ),
                region=config_client.region,
                all_aws_regions=False,
                aws_regions=None,
                organization_aggregation_source_present=False,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=synthetic)
            if delegated_admin_unknown:
                delegated_state = (
                    "delegated administrator status could not be determined"
                )
            elif has_delegated_admin:
                delegated_state = "delegated administrator configured"
            else:
                delegated_state = (
                    "no delegated administrator registered for config.amazonaws.com"
                )
            report.status = "FAIL"
            report.status_extended = (
                f"AWS Config has no Organization Aggregator configured in any "
                f"region ({delegated_state})."
            )
            findings.append(report)
            return findings

        for region, aggregators_in_region in config_client.aggregators.items():
            for aggregator in aggregators_in_region:
                report = Check_Report_AWS(metadata=self.metadata(), resource=aggregator)

                org_aware = aggregator.organization_aggregation_source_present
                covers_all = aggregator.all_aws_regions

                issues = []
                if delegated_admin_unknown:
                    issues.append(
                        "delegated administrator status for config.amazonaws.com "
                        "could not be determined"
                    )
                elif not has_delegated_admin:
                    issues.append(
                        "no delegated administrator registered for config.amazonaws.com"
                    )
                if not org_aware:
                    issues.append(
                        f"aggregator {aggregator.name} is not an organization aggregator"
                    )
                elif not covers_all:
                    issues.append(
                        f"aggregator {aggregator.name} does not cover all AWS regions"
                    )

                if issues:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"AWS Config aggregator {aggregator.name} in region "
                        f"{region} has issues: {', '.join(issues)}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"AWS Config aggregator {aggregator.name} in region "
                        f"{region} is an organization aggregator covering all "
                        f"AWS regions with delegated admin configured."
                    )

                # Support muting non-default regions if configured
                if report.status == "FAIL" and (
                    config_client.audit_config.get("mute_non_default_regions", False)
                    and region != config_client.region
                ):
                    report.muted = True

                findings.append(report)

        return findings
