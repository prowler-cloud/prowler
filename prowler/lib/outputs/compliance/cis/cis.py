from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color
from prowler.lib.check.compliance_config_eval import (
    get_effective_status,
    get_scan_audit_config,
    resolve_requirement_config_status,
)


def get_cis_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    sections = {}
    section_muted_seen = {}
    section_split_seen = {}
    provider = ""
    cis_compliance_table = {
        "Provider": [],
        "Section": [],
        "Level 1": [],
        "Level 2": [],
        "Muted": [],
    }
    pass_count = []
    fail_count = []
    muted_count = []
    # The applied config is scan-global (the provider's audit_config). Evaluate
    # each requirement's config constraints once against it (memoised by Id).
    audit_config = get_scan_audit_config()
    config_status_cache = {}
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            version_in_name = compliance_framework.split("_")[1]
            if compliance.Framework == "CIS" and version_in_name in compliance.Version:
                provider = compliance.Provider
                for requirement in compliance.Requirements:
                    # A requirement whose configurable checks ran with an invalid
                    # config can't be trusted: treat the finding as FAIL.
                    config_status = resolve_requirement_config_status(
                        requirement, audit_config, config_status_cache
                    )
                    effective_status = get_effective_status(
                        finding.status, config_status
                    )
                    for attribute in requirement.Attributes:
                        section = attribute.Section
                        # Check if Section exists
                        if section not in sections:
                            sections[section] = {
                                "Status": f"{Fore.GREEN}PASS{Style.RESET_ALL}",
                                "Level 1": {"FAIL": 0, "PASS": 0},
                                "Level 2": {"FAIL": 0, "PASS": 0},
                                "Muted": 0,
                            }
                            section_muted_seen[section] = set()
                            section_split_seen[section] = {
                                "Level 1": set(),
                                "Level 2": set(),
                            }
                        if finding.muted:
                            # Overview total: count each finding once per framework
                            if index not in muted_count:
                                muted_count.append(index)
                            # Per-section Muted: count each finding once per section
                            # it belongs to (a finding can map to several sections).
                            if index not in section_muted_seen[section]:
                                section_muted_seen[section].add(index)
                                sections[section]["Muted"] += 1
                        else:
                            if effective_status == "FAIL" and index not in fail_count:
                                fail_count.append(index)
                            elif effective_status == "PASS" and index not in pass_count:
                                pass_count.append(index)
                        if "Level 1" in attribute.Profile:
                            if (
                                not finding.muted
                                and index not in section_split_seen[section]["Level 1"]
                            ):
                                section_split_seen[section]["Level 1"].add(index)
                                if effective_status == "FAIL":
                                    sections[section]["Level 1"]["FAIL"] += 1
                                else:
                                    sections[section]["Level 1"]["PASS"] += 1
                        elif "Level 2" in attribute.Profile:
                            if (
                                not finding.muted
                                and index not in section_split_seen[section]["Level 2"]
                            ):
                                section_split_seen[section]["Level 2"].add(index)
                                if effective_status == "FAIL":
                                    sections[section]["Level 2"]["FAIL"] += 1
                                else:
                                    sections[section]["Level 2"]["PASS"] += 1

    # Add results to table
    sections = dict(sorted(sections.items()))
    for section in sections:
        cis_compliance_table["Provider"].append(provider)
        cis_compliance_table["Section"].append(section)
        if sections[section]["Level 1"]["FAIL"] > 0:
            cis_compliance_table["Level 1"].append(
                f"{Fore.RED}FAIL({sections[section]['Level 1']['FAIL']}){Style.RESET_ALL}"
            )
        else:
            cis_compliance_table["Level 1"].append(
                f"{Fore.GREEN}PASS({sections[section]['Level 1']['PASS']}){Style.RESET_ALL}"
            )
        if sections[section]["Level 2"]["FAIL"] > 0:
            cis_compliance_table["Level 2"].append(
                f"{Fore.RED}FAIL({sections[section]['Level 2']['FAIL']}){Style.RESET_ALL}"
            )
        else:
            cis_compliance_table["Level 2"].append(
                f"{Fore.GREEN}PASS({sections[section]['Level 2']['PASS']}){Style.RESET_ALL}"
            )
        cis_compliance_table["Muted"].append(
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
            print(
                f"\nFramework {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL} Results:"
            )
            print(
                tabulate(
                    cis_compliance_table,
                    headers="keys",
                    tablefmt="rounded_grid",
                )
            )
            print(
                f"{Style.BRIGHT}* Only sections containing results appear.{Style.RESET_ALL}"
            )
            print(f"\nDetailed results of {compliance_framework.upper()} are in:")
            print(
                f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework}.csv\n"
            )
