from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color


def get_cis_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    sections = {}
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
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if (
                compliance.Framework == "CIS"
                and compliance.Version in compliance_framework
            ):
                for requirement in compliance.Requirements:
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
                        if finding.muted:
                            if index not in muted_count:
                                muted_count.append(index)
                                sections[section]["Muted"] += 1
                        else:
                            if finding.status == "FAIL" and index not in fail_count:
                                fail_count.append(index)
                            elif finding.status == "PASS" and index not in pass_count:
                                pass_count.append(index)
                        if "Level 1" in attribute.Profile:
                            if not finding.muted:
                                if finding.status == "FAIL":
                                    sections[section]["Level 1"]["FAIL"] += 1
                                else:
                                    sections[section]["Level 1"]["PASS"] += 1
                        elif "Level 2" in attribute.Profile:
                            if not finding.muted:
                                if finding.status == "FAIL":
                                    sections[section]["Level 2"]["FAIL"] += 1
                                else:
                                    sections[section]["Level 2"]["PASS"] += 1

    # Add results to table
    sections = dict(sorted(sections.items()))
    for section in sections:
        cis_compliance_table["Provider"].append(compliance.Provider)
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
