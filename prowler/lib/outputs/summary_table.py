import sys

from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
    orange_color,
)
from prowler.lib.logger import logger
from prowler.providers.github.models import GithubAppIdentityInfo, GithubIdentityInfo


def display_summary_table(
    findings: list,
    provider,
    output_options,
):
    output_directory = output_options.output_directory
    output_filename = output_options.output_filename
    try:
        if provider.type == "aws":
            entity_type = "Account"
            audited_entities = provider.identity.account
        elif provider.type == "azure":
            if (
                provider.identity.tenant_domain
                != "Unknown tenant domain (missing AAD permissions)"
            ):
                entity_type = "Tenant Domain"
                audited_entities = provider.identity.tenant_domain
            else:
                entity_type = "Tenant ID/s"
                audited_entities = " ".join(provider.identity.tenant_ids)
        elif provider.type == "gcp":
            entity_type = "Project ID/s"
            audited_entities = ", ".join(provider.project_ids)
        elif provider.type == "kubernetes":
            entity_type = "Context"
            audited_entities = provider.identity.context
        elif provider.type == "github":
            if isinstance(provider.identity, GithubIdentityInfo):
                entity_type = "User Name"
                audited_entities = provider.identity.account_name
            elif isinstance(provider.identity, GithubAppIdentityInfo):
                entity_type = "App ID"
                audited_entities = provider.identity.app_id
        elif provider.type == "m365":
            entity_type = "Tenant Domain"
            audited_entities = provider.identity.tenant_domain
        elif provider.type == "googleworkspace":
            entity_type = "Domain"
            audited_entities = provider.identity.domain
        elif provider.type == "mongodbatlas":
            entity_type = "Organization"
            audited_entities = provider.identity.organization_name
        elif provider.type == "cloudflare":
            entity_type = "Account"
            audited_accounts = getattr(provider.identity, "audited_accounts", []) or []
            if audited_accounts:
                audited_entities = ", ".join(audited_accounts)
            else:
                audited_entities = (
                    getattr(provider.identity, "email", None) or "Cloudflare"
                )
        elif provider.type == "nhn":
            entity_type = "Tenant Domain"
            audited_entities = provider.identity.tenant_domain
        elif provider.type == "iac":
            if provider.scan_repository_url:
                entity_type = "Repository"
                audited_entities = provider.scan_repository_url
            else:
                entity_type = "Directory"
                audited_entities = provider.scan_path
        elif provider.type == "llm":
            entity_type = "LLM"
            audited_entities = provider.model
        elif provider.type == "oraclecloud":
            entity_type = "Tenancy"
            audited_entities = (
                provider.identity.tenancy_name
                if provider.identity.tenancy_name != "unknown"
                else provider.identity.tenancy_id
            )
        elif provider.type == "alibabacloud":
            entity_type = "Account"
            audited_entities = provider.identity.account_id
        elif provider.type == "openstack":
            entity_type = "Project"
            audited_entities = (
                provider.identity.project_name
                if provider.identity.project_name
                else provider.identity.project_id
            )
        elif provider.type == "image":
            entity_type = "Image"
            audited_entities = ", ".join(provider.images)

        # Check if there are findings and that they are not all MANUAL
        if findings and not all(finding.status == "MANUAL" for finding in findings):
            current = {
                "Service": "",
                "Provider": "",
                "Total": 0,
                "Pass": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Muted": 0,
            }
            findings_table = {
                "Provider": [],
                "Service": [],
                "Status": [],
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
                "Muted": [],
            }
            pass_count = fail_count = muted_count = 0
            # Sort findings by ServiceName
            findings.sort(key=lambda x: x.check_metadata.ServiceName)
            for finding in findings:
                # If new service and not first, add previous row
                if (
                    current["Service"] != finding.check_metadata.ServiceName
                    and current["Service"]
                ):
                    add_service_to_table(findings_table, current)

                    current["Total"] = current["Pass"] = current["Muted"] = current[
                        "Critical"
                    ] = current["High"] = current["Medium"] = current["Low"] = 0

                current["Service"] = finding.check_metadata.ServiceName
                current["Provider"] = finding.check_metadata.Provider

                current["Total"] += 1
                if finding.muted:
                    muted_count += 1
                    current["Muted"] += 1
                if finding.status == "PASS":
                    pass_count += 1
                    current["Pass"] += 1
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
                    f"{Fore.RED}{round(fail_count / len(findings) * 100, 2)}% ({fail_count}) Failed{Style.RESET_ALL}",
                    f"{Fore.GREEN}{round(pass_count / len(findings) * 100, 2)}% ({pass_count}) Passed{Style.RESET_ALL}",
                    f"{orange_color}{round(muted_count / len(findings) * 100, 2)}% ({muted_count}) Muted{Style.RESET_ALL}",
                ]
            ]
            print(tabulate(overview_table, tablefmt="rounded_grid"))

            print(
                f"\n{entity_type} {Fore.YELLOW}{audited_entities}{Style.RESET_ALL} Scan Results (severity columns are for fails only):"
            )
            if provider == "azure":
                print(
                    f"\nSubscriptions scanned: {Fore.YELLOW}{' '.join(provider.identity.subscriptions.keys())}{Style.RESET_ALL}"
                )
            print(tabulate(findings_table, headers="keys", tablefmt="rounded_grid"))
            print(
                f"{Style.BRIGHT}* You only see here those services that contains resources.{Style.RESET_ALL}"
            )
            print("\nDetailed results are in:")
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
            if "html" in output_options.output_modes:
                print(
                    f" - HTML: {output_directory}/{output_filename}{html_file_suffix}"
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
        current["Status"] = f"{Fore.GREEN}PASS ({current['Pass']}){Style.RESET_ALL}"

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
    findings_table["Muted"].append(f"{orange_color}{current['Muted']}{Style.RESET_ALL}")
