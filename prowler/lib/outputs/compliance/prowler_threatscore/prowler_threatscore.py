from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color


def get_prowler_threatscore_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    pillar_table = {
        "Provider": [],
        "Pillar": [],
        "Status": [],
        "Muted": [],
        "Score": [],
    }
    pass_count = []
    fail_count = []
    muted_count = []
    pillars = {}
    score_per_pillar = {}
    number_findings_per_pillar = {}
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if compliance.Framework == "ProwlerThreatScore":
                for requirement in compliance.Requirements:
                    for attribute in requirement.Attributes:
                        pillar = attribute.Section

                        if pillar not in score_per_pillar.keys():
                            score_per_pillar[pillar] = 0
                            number_findings_per_pillar[pillar] = 0
                        if finding.status == "FAIL" and not finding.muted:
                            score_per_pillar[pillar] += attribute.LevelOfRisk
                            number_findings_per_pillar[pillar] += 1

                        if pillar not in pillars:
                            pillars[pillar] = {"FAIL": 0, "PASS": 0, "Muted": 0}

                        if finding.muted:
                            if index not in muted_count:
                                muted_count.append(index)
                                pillars[pillar]["Muted"] += 1
                        else:
                            if finding.status == "FAIL" and index not in fail_count:
                                fail_count.append(index)
                                pillars[pillar]["FAIL"] += 1
                            elif finding.status == "PASS" and index not in pass_count:
                                pass_count.append(index)
                                pillars[pillar]["PASS"] += 1

    pillars = dict(sorted(pillars.items()))
    for pillar in pillars:
        pillar_table["Provider"].append(compliance.Provider)
        pillar_table["Pillar"].append(pillar)
        if number_findings_per_pillar[pillar] == 0:
            pillar_table["Score"].append(f"{Fore.MAGENTA}0{Style.RESET_ALL}")
        else:
            pillar_table["Score"].append(
                f"{Fore.MAGENTA}{score_per_pillar[pillar] / number_findings_per_pillar[pillar]:.2f}/5{Style.RESET_ALL}"
            )
        if pillars[pillar]["FAIL"] > 0:
            pillar_table["Status"].append(
                f"{Fore.RED}FAIL({pillars[pillar]['FAIL']}){Style.RESET_ALL}"
            )
        else:
            pillar_table["Status"].append(
                f"{Fore.GREEN}PASS({pillars[pillar]['PASS']}){Style.RESET_ALL}"
            )
        pillar_table["Muted"].append(
            f"{orange_color}{pillars[pillar]['Muted']}{Style.RESET_ALL}"
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
            if len(fail_count) > 0 and len(pillar_table["Pillar"]) > 0:
                print(
                    f"\nFramework {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL} Results:"
                )

                print(
                    tabulate(
                        pillar_table,
                        tablefmt="rounded_grid",
                        headers="keys",
                    )
                )

                print(
                    f"{Style.BRIGHT}{Fore.MAGENTA}\n=== Risk Score Guide ===\nScore ranges from 1 (lowest risk) to 5 (highest risk), indicating the severity of the potential impact.\n{Style.RESET_ALL}"
                )
                print(
                    f"{Style.BRIGHT}* Only sections containing results appear, {orange_color}The score is calculated as the sum of the level of risk of the failed findings divided by the number of failed findings.{Style.RESET_ALL}"
                )
                print(f"\nDetailed results of {compliance_framework.upper()} are in:")
                print(
                    f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework}.csv\n"
                )
