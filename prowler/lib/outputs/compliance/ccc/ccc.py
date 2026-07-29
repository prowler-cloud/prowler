from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color
from prowler.lib.check.compliance_config_eval import (
    accumulate_group_status,
    accumulate_overview_status,
    get_effective_status,
    get_scan_audit_config,
    resolve_requirement_config_status,
)


def get_ccc_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    section_table = {
        "Provider": [],
        "Section": [],
        "Status": [],
        "Muted": [],
    }
    pass_count = set()
    fail_count = set()
    muted_count = set()
    sections = {}
    section_seen = {}
    provider = ""
    audit_config = get_scan_audit_config()
    config_status_cache = {}
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if compliance.Framework == "CCC":
                provider = compliance.Provider
                for requirement in compliance.Requirements:
                    config_status = resolve_requirement_config_status(
                        requirement, audit_config, config_status_cache
                    )
                    effective_status = get_effective_status(
                        finding.status, config_status
                    )
                    for attribute in requirement.Attributes:
                        section = attribute.Section

                        if section not in sections:
                            sections[section] = {"FAIL": 0, "PASS": 0, "Muted": 0}
                            section_seen[section] = {}

                        status = "Muted" if finding.muted else effective_status
                        accumulate_overview_status(
                            index, status, pass_count, fail_count, muted_count
                        )
                        accumulate_group_status(
                            index, status, sections[section], section_seen[section]
                        )

    sections = dict(sorted(sections.items()))
    for section in sections:
        section_table["Provider"].append(provider)
        section_table["Section"].append(section)
        if sections[section]["FAIL"] > 0:
            section_table["Status"].append(
                f"{Fore.RED}FAIL({sections[section]['FAIL']}){Style.RESET_ALL}"
            )
        else:
            if sections[section]["PASS"] > 0:
                section_table["Status"].append(
                    f"{Fore.GREEN}PASS({sections[section]['PASS']}){Style.RESET_ALL}"
                )
            else:
                section_table["Status"].append(f"{Fore.GREEN}PASS{Style.RESET_ALL}")
        section_table["Muted"].append(
            f"{orange_color}{sections[section]['Muted']}{Style.RESET_ALL}"
        )

    if (
        len(fail_count) + len(pass_count) + len(muted_count) > 1
    ):  # If there are no resources, don't print the compliance table
        print(
            f"\nCompliance Status of {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL} Framework:"
        )
        total_findings_count = len(fail_count) + len(pass_count) + len(muted_count)
        overview_table = [
            [
                f"{Fore.RED}{round(len(fail_count) / total_findings_count * 100, 2)}% ({len(fail_count)}) FAIL{Style.RESET_ALL}",
                f"{Fore.GREEN}{round(len(pass_count) / total_findings_count * 100, 2)}% ({len(pass_count)}) PASS{Style.RESET_ALL}",
                f"{orange_color}{round(len(muted_count) / total_findings_count * 100, 2)}% ({len(muted_count)}) MUTED{Style.RESET_ALL}",
            ]
        ]
        print(tabulate(overview_table, tablefmt="rounded_grid"))
        if not compliance_overview:
            if len(fail_count) > 0 and len(section_table["Section"]) > 0:
                print(
                    f"\nFramework {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL} Results:"
                )
                print(
                    tabulate(
                        section_table,
                        tablefmt="rounded_grid",
                        headers="keys",
                    )
                )
                print(f"\nDetailed results of {compliance_framework.upper()} are in:")
                print(
                    f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework}.csv\n"
                )
