from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import secretsmanager_client


class secretsmanager_scheduled_rotation_success_check(Check):
    def execute(self):
        findings = []

        # Iterate through all secrets
        for secret in secretsmanager_client.secrets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = secret.region
            report.resource_id = secret.name
            report.resource_arn = secret.arn
            report.resource_tags = secret.tags

            # Check if the secret has rotation enabled
            if secret.rotation_enabled:
                try:
                    # Fetch secret details to check rotation information
                    secret_details = secretsmanager_client.provider.client(
                        "secretsmanager", region_name=secret.region
                    ).describe_secret(SecretId=secret.arn)
                    last_rotated_date = secret_details.get("LastRotatedDate")
                    next_rotation_date = secret_details.get("NextRotationDate")

                    if next_rotation_date and last_rotated_date and next_rotation_date > last_rotated_date:
                        report.status = "PASS"
                        report.status_extended = (
                            f"SecretsManager secret {secret.name} has successfully rotated according to the schedule."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"SecretsManager secret {secret.name} did not rotate as scheduled."
                        )
                except Exception as e:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Failed to retrieve rotation details for secret {secret.name}: {str(e)}"
                    )
            else:
                report.status = "MANUAL"
                report.status_extended = (
                    f"SecretsManager secret {secret.name} does not have rotation enabled. Manual review required."
                )

            findings.append(report)

        return findings
