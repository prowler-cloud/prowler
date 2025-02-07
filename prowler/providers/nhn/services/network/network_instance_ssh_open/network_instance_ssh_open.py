# from prowler.lib.check.models import Check, Check_Report_NHN
# from prowler.providers.nhn.services.compute.compute_client import compute_client

# class network_server_ssh_open(Check):
#     def execute(self):
#         findings = []
#         for network in compute_client.networks:
#             report = Check_Report_NHN(metadata=self.metadata(), resource=network)
#             report.status = "PASS"
#             report.status_extended = f"VM Instance {instance.name} does not have a public SSH."
#             if network.ssh_open:
#                 report.status = "FAIL"
#                 report.status_extended = f"VM Instance {instance.name} has a public SSH."
#             findings.append(report)

#         return findings
