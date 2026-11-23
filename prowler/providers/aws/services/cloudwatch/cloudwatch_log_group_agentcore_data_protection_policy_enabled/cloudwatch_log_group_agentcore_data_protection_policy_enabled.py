from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client

# Log group name prefixes AgentCore uses for agent telemetry. The runtime creates
# /aws/bedrock-agentcore/runtimes/... itself. Log delivery for memory, gateway and built-in tool
# resources is CONFIGURED by the operator rather than defaulted -- the AgentCore devguide's
# observability-configure page is a put_delivery_source / put_delivery_destination /
# create_delivery procedure -- and it targets /aws/vendedlogs/bedrock-agentcore/... because for
# same-account delivery to a /aws/vendedlogs/ log group the log-delivery service-linked role
# grants write access implicitly, while any other destination needs an explicit resource policy
# or the delivery silently fails. So the prefix is the convention that makes delivery work, which
# is why these two and not others.
DEFAULT_AGENTCORE_LOG_GROUP_PREFIXES = [
    "/aws/bedrock-agentcore/",
    "/aws/vendedlogs/bedrock-agentcore/",
]

ACTIVATED = "ACTIVATED"
ACCOUNT_DATA_PROTECTION = "ACCOUNT_DATA_PROTECTION"


class cloudwatch_log_group_agentcore_data_protection_policy_enabled(Check):
    """Ensure AgentCore log groups mask sensitive data with a data protection policy.

    Agents write prompts, tool arguments and retrieved context to their own log groups. A data
    protection policy masks matched data at ingestion, so without one the values are stored in
    clear text and readable by every principal holding logs:GetLogEvents.

    Scope: log groups whose name starts with an AgentCore prefix. AgentCore log delivery can be
    pointed at an arbitrarily named log group, so the prefix list is configurable through
    agentcore_log_group_name_prefixes; a configured list REPLACES the defaults rather than
    extending them, and an explicitly null value falls back to the defaults.

    PASS when the log group has an ACTIVATED policy of its own, or inherits the account-level one.
    FAIL when dataProtectionStatus is DELETED, ARCHIVED or DISABLED, or was never reported: all
    four mean nothing is being masked at ingestion today.
    MANUAL when the log group inventory could not be read, because nothing is then known about any
    log group's masking. Only a denied DescribeLogGroups leaves the inventory unknown -- every
    other collector failure leaves a readable, possibly partial, inventory.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the AgentCore log group data protection policy check.

        Returns:
            A list of reports containing the result of the check: one per in-scope
            AgentCore log group, or a single account-level report when the log group
            inventory could not be read.
        """
        findings = []

        # An ABSENT or explicitly null value falls back to the defaults; an empty LIST does not.
        # `is None` covers both a missing key and a bare `agentcore_log_group_name_prefixes:` in the
        # YAML, which parses as None, and both mean "not configured". `or` additionally swallowed an
        # explicitly empty list, which IS a configured value and the one way an operator can say "no
        # log group is in scope" -- so the fallback overrode the operator and contradicted the
        # REPLACES-the-defaults behaviour promised above. An empty tuple is meaningful downstream
        # rather than degenerate: str.startswith(()) is False for every name, so nothing is selected,
        # which is exactly the request.
        configured_prefixes = logs_client.audit_config.get(
            "agentcore_log_group_name_prefixes"
        )
        prefixes = tuple(
            DEFAULT_AGENTCORE_LOG_GROUP_PREFIXES
            if configured_prefixes is None
            else configured_prefixes
        )

        # An unreadable log group inventory must not read as compliant: without the
        # inventory there is no way to tell an AgentCore log group that masks
        # sensitive data from one that does not.
        if logs_client.log_groups is None:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.status = "MANUAL"
            report.status_extended = "Log groups could not be retrieved, so data protection policies for AgentCore log groups could not be verified."
            report.region = logs_client.region
            report.resource_id = logs_client.audited_account
            report.resource_arn = logs_client.log_group_arn_template
            report.resource_tags = []
            return [report]

        for log_group in logs_client.log_groups.values():
            if not log_group.name.startswith(prefixes):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)
            if log_group.data_protection_status == ACTIVATED:
                report.status = "PASS"
                report.status_extended = f"AgentCore log group {log_group.name} has a data protection policy activated."
            elif ACCOUNT_DATA_PROTECTION in log_group.inherited_properties:
                report.status = "PASS"
                report.status_extended = f"AgentCore log group {log_group.name} inherits the account-level data protection policy."
            else:
                report.status = "FAIL"
                report.status_extended = f"AgentCore log group {log_group.name} does not have an active data protection policy, so sensitive data written by the agent is not masked."
            findings.append(report)

        return findings
