from prowler.lib.check.models import Check, Check_Report_Azure


class appinsights_ensure_is_configured(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        # for (
        #         subscription_name,
        #         <foo>,
        #     ) in appinsights_client.<foo>.items():

        #     report = Check_Report_Azure(self.metadata())
        #     # Aqui suele ir un for para iterar sobre <foo> // for <fo> in <foo>:
        #         report.status = "PASS"
        #         report.subscription = subscription_name
        #         report.resource_name = contac_name
        #         report.resource_id = contact_info.resource_id
        #         report.status_extended = f"<foo> for susbscription <subscription_name>."

        #         # Lógica de la validación por si no se pasa el test
        #         if not <foo>:
        #             report.status = "FAIL"
        #             report.status_extended = f"<foo> for subscription <subscription_name>."

        #         findings.append(report)

        return findings
