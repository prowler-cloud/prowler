import sys

from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.logger import logger
from prowler.providers.common.outputs import Provider_Output_Options


def display_summary_table(
    findings: list,
    audit_info,
    output_options: Provider_Output_Options,
    provider: str,
):
    output_directory = output_options.output_directory
    output_filename = output_options.output_filename
    try:
        if provider == "aws":
            entity_type = "Account"
            audited_entities = audit_info.audited_account
        elif provider == "azure":
            if (
                audit_info.identity.domain
                != "Unknown tenant domain (missing AAD permissions)"
            ):
                entity_type = "Tenant Domain"
                audited_entities = audit_info.identity.domain
            else:
                entity_type = "Tenant ID/s"
                audited_entities = " ".join(audit_info.identity.tenant_ids)
        elif provider == "gcp":
            entity_type = "Project ID/s"
            audited_entities = ", ".join(audit_info.project_ids)

        if findings:
            current = {
                "Service": "",
                "Provider": "",
                "Total": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
            }
            findings_table = {
                "Provider": [],
                "Service": [],
                "Status": [],
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                # If new service and not first, add previous row
                if (
                    current["Service"] != finding.check_metadata.ServiceName
                    and current["Service"]
                ):
                    add_service_to_table(findings_table, current)

                    current["Total"] = current["Critical"] = current["High"] = current[
                        "Medium"
                    ] = current["Low"] = 0

                current["Service"] = finding.check_metadata.ServiceName
                current["Provider"] = finding.check_metadata.Provider

                current["Total"] += 1
                if finding.status == "PASS":
                    pass_count += 1
                elif finding.status == "FAIL":
                    fail_count += 1
                    if finding.check_metadata.Severity == "critical":
                        current["Critical"] += 1
                    elif finding.check_metadata.Severity == "high":
                        current["High"] += 1
                    elif finding.check_metadata.Severity == "medium":
                        current["Medium"] += 1
                    elif finding.check_metadata.Severity == "low":
                        current["Low"] += 1

            # Add final service

            add_service_to_table(findings_table, current)

            print("\nOverview Results:")
            overview_table = [
                [
                    f"{Fore.RED}{round(fail_count/len(findings)*100, 2)}% ({fail_count}) Failed{Style.RESET_ALL}",
                    f"{Fore.GREEN}{round(pass_count/len(findings)*100, 2)}% ({pass_count}) Passed{Style.RESET_ALL}",
                ]
            ]
            print(tabulate(overview_table, tablefmt="rounded_grid"))

            print(
                f"\n{entity_type} {Fore.YELLOW}{audited_entities}{Style.RESET_ALL} Scan Results (severity columns are for fails only):"
            )
            if provider == "azure":
                print(
                    f"\nSubscriptions scanned: {Fore.YELLOW}{' '.join(audit_info.identity.subscriptions.keys())}{Style.RESET_ALL}"
                )
            print(tabulate(findings_table, headers="keys", tablefmt="rounded_grid"))
            print(
                f"{Style.BRIGHT}* You only see here those services that contains resources.{Style.RESET_ALL}"
            )
            print("\nDetailed results are in:")
            if "html" in output_options.output_modes:
                print(
                    f" - HTML: {output_directory}/{output_filename}{html_file_suffix}"
                )
            if "json-asff" in output_options.output_modes:
                print(
                    f" - JSON-ASFF: {output_directory}/{output_filename}{json_asff_file_suffix}"
                )
            if "json-ocsf" in output_options.output_modes:
                print(
                    f" - JSON-OCSF: {output_directory}/{output_filename}{json_ocsf_file_suffix}"
                )
            if "csv" in output_options.output_modes:
                print(f" - CSV: {output_directory}/{output_filename}{csv_file_suffix}")
            if "json" in output_options.output_modes:
                print(
                    f" - JSON: {output_directory}/{output_filename}{json_file_suffix}"
                )

        else:
            print(
                f"\n {Style.BRIGHT}There are no findings in {entity_type} {Fore.YELLOW}{audited_entities}{Style.RESET_ALL}\n"
            )

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
        )
        sys.exit(1)


def add_service_to_table(findings_table, current):
    if (
        current["Critical"] > 0
        or current["High"] > 0
        or current["Medium"] > 0
        or current["Low"] > 0
    ):
        total_fails = (
            current["Critical"] + current["High"] + current["Medium"] + current["Low"]
        )
        current["Status"] = f"{Fore.RED}FAIL ({total_fails}){Style.RESET_ALL}"
    else:
        current["Status"] = f"{Fore.GREEN}PASS ({current['Total']}){Style.RESET_ALL}"
    findings_table["Provider"].append(current["Provider"])
    findings_table["Service"].append(current["Service"])
    findings_table["Status"].append(current["Status"])
    findings_table["Critical"].append(
        f"{Fore.LIGHTRED_EX}{current['Critical']}{Style.RESET_ALL}"
    )
    findings_table["High"].append(f"{Fore.RED}{current['High']}{Style.RESET_ALL}")
    findings_table["Medium"].append(
        f"{Fore.YELLOW}{current['Medium']}{Style.RESET_ALL}"
    )
    findings_table["Low"].append(f"{Fore.BLUE}{current['Low']}{Style.RESET_ALL}")
