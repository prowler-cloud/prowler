from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_rcps_enforce_encryption(Check):
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
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} does not have Resource Control Policies enforcing encryption requirements."

                    # Check if Resource Control Policies are present
                    if (
                        "RESOURCE_CONTROL_POLICY"
                        in organizations_client.organization.policies
                    ):
                        rcps = organizations_client.organization.policies.get(
                            "RESOURCE_CONTROL_POLICY", []
                        )

                        # Check for encryption-related RCPs
                        encryption_rcps = []
                        for policy in rcps:
                            # Check if policy enforces encryption
                            if self._policy_enforces_encryption(policy):
                                encryption_rcps.append(policy)

                        if encryption_rcps:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has {len(encryption_rcps)} Resource Control Policies enforcing encryption requirements."

                findings.append(report)

        return findings

    def _policy_enforces_encryption(self, policy):
        """Check if a policy enforces encryption requirements"""
        # Get policy statements
        statements = policy.content.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        # Keywords and conditions that indicate encryption enforcement
        encryption_keywords = [
            "encrypted",
            "encryption",
            "kms",
            "sse",
            "server-side-encryption",
            "tls",
            "ssl",
            "https",
            "secure-transport",
        ]

        # Known encryption-related conditions
        encryption_conditions = [
            "s3:x-amz-server-side-encryption",
            "ec2:Encrypted",
            "kms:EncryptionContext",
            "dynamodb:Encrypted",
            "rds:StorageEncrypted",
            "secretsmanager:SecretString",
            "lambda:SecretString",
            "sagemaker:VolumeKmsKey",
        ]

        # Check statements for encryption enforcement
        for statement in statements:
            # If the statement denies actions when encryption is not enabled
            if statement.get("Effect") == "Deny":
                # Check conditions
                condition = statement.get("Condition", {})
                condition_str = str(condition).lower()

                # Check for encryption-related conditions
                for keyword in encryption_keywords:
                    if keyword in condition_str:
                        return True

                # Check for known encryption conditions
                for enc_condition in encryption_conditions:
                    if enc_condition in str(condition):
                        return True

                # Check if any actions are related to encryption
                actions = statement.get("Action", [])
                if not isinstance(actions, list):
                    actions = [actions]

                for action in actions:
                    action = action.lower() if isinstance(action, str) else ""
                    # Check if action involves encryption
                    if any(
                        keyword in action for keyword in ["encrypt", "decrypt", "kms"]
                    ):
                        return True

        # If no encryption enforcement found
        return False
