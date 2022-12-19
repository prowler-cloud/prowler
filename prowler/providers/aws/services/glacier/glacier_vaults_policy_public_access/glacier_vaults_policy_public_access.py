from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glacier.glacier_client import glacier_client


class glacier_vaults_policy_public_access(Check):
    def execute(self):
        findings = []
        for vault in glacier_client.vaults.values():
            report = Check_Report_AWS(self.metadata())
            report.region = vault.region
            report.resource_id = vault.name
            report.resource_arn = vault.arn

            report.status = "PASS"
            report.status_extended = (
                f"Vault {vault.name} has policy which does not allow access to everyone"
            )

            public_access = False
            if vault.access_policy:
                for statement in vault.access_policy["Statement"]:

                    # Only check allow statements
                    if statement["Effect"] == "Allow":

                        if (
                            "*" in statement["Principal"]
                            or (
                                "AWS" in statement["Principal"]
                                and "*" in statement["Principal"]["AWS"]
                            )
                            or (
                                "CanonicalUser" in statement["Principal"]
                                and "*" in statement["Principal"]["CanonicalUser"]
                            )
                        ):
                            public_access = True
                            break

            if public_access:
                report.status = "FAIL"
                report.status_extended = (
                    f"Vault {vault.name} has policy which allows access to everyone"
                )

            findings.append(report)

        return findings
