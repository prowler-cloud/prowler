from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_rcps_enforce_logging_monitoring(Check):
    def execute(self):
        findings = []

        if organizations_client.organization:
            if organizations_client.organization.policies is not None:
                report = Check_Report_AWS(
                    metadata=self.metadata(),
                    resource=organizations_client.organization,
                )
                report.resource_id = organizations_client.organization.id
                report.resource_arn = organizations_client.organization.arn
                report.region = organizations_client.region
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account."
                )

                if organizations_client.organization.status == "ACTIVE":
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} does not have Resource Control Policies enforcing logging and monitoring controls."

                    # Check if Resource Control Policies are present
                    if (
                        "RESOURCE_CONTROL_POLICY"
                        in organizations_client.organization.policies
                    ):
                        rcps = organizations_client.organization.policies.get(
                            "RESOURCE_CONTROL_POLICY", []
                        )

                        # Check for logging and monitoring controls in RCPs
                        logging_monitoring_rcps = []
                        for policy in rcps:
                            # Check if policy enforces logging and monitoring controls
                            if self._policy_enforces_logging_monitoring(policy):
                                logging_monitoring_rcps.append(policy)

                        if logging_monitoring_rcps:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has {len(logging_monitoring_rcps)} Resource Control Policies enforcing logging and monitoring controls."

                findings.append(report)

        return findings

    def _policy_enforces_logging_monitoring(self, policy):
        """Check if a policy enforces logging and monitoring controls"""
        # Get policy statements
        statements = policy.content.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        # Logging and monitoring related services
        logging_services = [
            "cloudtrail",
            "cloudwatch",
            "logs",
            "config",
            "securityhub",
            "guardduty",
            "s3:logdelivery",
            "logging",
            "kinesisanalytics",
            "kinesis",
            "events",
            "firehose",
            "sns",
            "eventbridge",
        ]

        # Specific logging and monitoring related actions
        logging_actions = [
            "stoplogging",
            "deletetrail",
            "updatetrail",
            "deleteloggingconfiguration",
            "disablelogs",
            "putretentionpolicy",
            "deletemetricfilter",
            "putbucketlogging",
            "deleteloggingpolicy",
            "putloggingoptions",
            "disableeventselection",
            "deleteeventdatastore",
            "disableall",
            "deregister",
            "deletealarm",
            "disableimportfindings",
            "disablelogging",
            "deletesubscription",
        ]

        # Logging and monitoring related conditions
        logging_conditions = [
            "logging",
            "log",
            "trail",
            "monitor",
            "cloudtrail",
            "cloudwatch",
            "aws:loggingEnabled",
            "s3:LoggingEnabled",
        ]

        # Check statements for logging and monitoring controls
        for statement in statements:
            # Check if statement is about preventing logging disablement
            if statement.get("Effect") == "Deny":
                # Check actions
                actions = statement.get("Action", [])
                if not isinstance(actions, list):
                    actions = [actions]

                action_str = str(actions).lower()

                # Check for logging-related services in actions
                for service in logging_services:
                    if service.lower() in action_str:
                        # Check for specific logging actions that should be denied
                        for logging_action in logging_actions:
                            if logging_action.lower() in action_str:
                                return True

                # Check conditions for logging-related conditions
                condition = statement.get("Condition", {})
                condition_str = str(condition).lower()

                for log_condition in logging_conditions:
                    if log_condition.lower() in condition_str:
                        return True

            # Check if statement requires logging to be enabled
            elif "Resource" in statement:
                resource = statement.get("Resource", "")
                # Check if resource includes logging-related resources
                for service in logging_services:
                    if (
                        isinstance(resource, str)
                        and service.lower() in resource.lower()
                    ):
                        # Check conditions for logging requirements
                        condition = statement.get("Condition", {})
                        if condition:
                            condition_str = str(condition).lower()
                            for log_condition in logging_conditions:
                                if log_condition.lower() in condition_str:
                                    return True

        # If no logging and monitoring controls found
        return False
