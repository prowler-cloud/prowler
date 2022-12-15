import shodan

from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_elastic_ip_shodan(Check):
    def execute(self):
        findings = []
        shodan_api_key = get_config_var("shodan_api_key")
        if shodan_api_key:
            api = shodan.Shodan(shodan_api_key)
            for eip in ec2_client.elastic_ips:
                report = Check_Report_AWS(self.metadata())
                report.region = eip.region
                if eip.public_ip:
                    try:
                        shodan_info = api.host(eip.public_ip)
                        report.status = "FAIL"
                        report.status_extended = f"Elastic IP {eip.public_ip} listed in Shodan with open ports {str(shodan_info['ports'])} and ISP {shodan_info['isp']} in {shodan_info['country_name']}. More info https://www.shodan.io/host/{eip.public_ip}"
                        report.resource_id = eip.public_ip
                        findings.append(report)
                    except shodan.APIError as error:
                        if "No information available for that IP" in error.value:
                            report.status = "PASS"
                            report.status_extended = (
                                f"Elastic IP {eip.public_ip} is not listed in Shodan."
                            )
                            report.resource_id = eip.public_ip
                            findings.append(report)
                            continue
                        else:
                            logger.error(f"Unknown Shodan API Error: {error.value}")

        else:
            logger.error(
                "ERROR: No Shodan API Key -- Please input a Shodan API Key with -N/--shodan or in config.yaml"
            )
        return findings
