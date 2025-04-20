from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.acc.acc_client import acc_client


class acc_auth_methods(Check):
    def execute(self):
        findings = []
        logger.info("Evaluating OpenNebula user authentication methods")
        auth_drivers = set()
        users_with_core = []
        users_with_stronger_auth = []
        for user in acc_client.users:
            # Ignore OpenNebula internal system accounts
            if user.auth_driver != "server_cipher":
                auth_drivers.add(user.auth_driver)
                if user.auth_driver == "core":
                    users_with_core.append(user.name)
                else:
                    users_with_stronger_auth.append(user.name)

        report = Check_Report_OpenNebula(
            metadata=self.metadata(),
            resource=user,
        )

        if auth_drivers == {"core"}:
            report.status = "FAIL"
            report.status_extended = (
                "All OpenNebula users use only the 'core' authentication driver (username and password). It is recommended to integrate stronger authentication methods such as LDAP, SSH, or x509."
            )
        elif users_with_core and users_with_stronger_auth:
            report.status = "MANUAL"
            report.status_extended = (
                f"Some users use 'core' authentication ({', '.join(users_with_core)}), while others ({', '.join(users_with_stronger_auth)}) use stronger methods: {', '.join(set(auth_drivers) - {'core'})}."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"All users use stronger authentication drivers: {', '.join(auth_drivers)}."
            )
        findings.append(report)
        return findings