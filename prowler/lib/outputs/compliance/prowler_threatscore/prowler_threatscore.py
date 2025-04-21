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
    threatscore_compliance_table = {
        "Pillar": [],
        "Sub-Pillar": [],
        "Score": [],
    }
    pass_count = []
    fail_count = []
    muted_count = []
    score_per_sub_pillar = {}
    number_findings_per_sub_pillar = {}
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if compliance.Framework == "ProwlerThreatScore":
                for requirement in compliance.Requirements:
                    for attribute in requirement.Attributes:
                        sub_pillar = attribute.SubSection

                        if sub_pillar not in score_per_sub_pillar.keys():
                            score_per_sub_pillar[sub_pillar] = 0
                            number_findings_per_sub_pillar[sub_pillar] = 0
                        if finding.status == "FAIL":
                            score_per_sub_pillar[sub_pillar] += attribute.LevelOfRisk
                            number_findings_per_sub_pillar[sub_pillar] += 1
                        if finding.muted and index not in muted_count:
                            muted_count.append(index)
                        else:
                            if finding.status == "FAIL" and index not in fail_count:
                                fail_count.append(index)
                            elif finding.status == "PASS" and index not in pass_count:
                                pass_count.append(index)

    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if compliance.Framework == "ProwlerThreatScore":
                for requirement in compliance.Requirements:
                    for attribute in requirement.Attributes:
                        if (
                            attribute.SubSection
                            not in threatscore_compliance_table["Sub-Pillar"]
                        ):
                            threatscore_compliance_table["Pillar"].append(
                                f"{Fore.YELLOW}{attribute.Section}{Style.RESET_ALL}"
                            )
                            threatscore_compliance_table["Sub-Pillar"].append(
                                attribute.SubSection
                            )
                            if (
                                number_findings_per_sub_pillar[attribute.SubSection]
                                == 0
                            ):
                                threatscore_compliance_table["Score"].append(
                                    f"{orange_color}0{Style.RESET_ALL}"
                                )
                            else:
                                threatscore_compliance_table["Score"].append(
                                    f"{orange_color}{score_per_sub_pillar[attribute.SubSection] / number_findings_per_sub_pillar[attribute.SubSection]:.2f}{Style.RESET_ALL}"
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
            if len(threatscore_compliance_table["Pillar"]) > 0 and len(fail_count) > 0:
                combined = list(
                    zip(
                        threatscore_compliance_table["Sub-Pillar"],
                        threatscore_compliance_table["Pillar"],
                        threatscore_compliance_table["Score"],
                    )
                )
                combined.sort(key=lambda x: x[0])
                sub_pillars_sorted, pillars_sorted, scores_sorted = zip(*combined)

                threatscore_compliance_table["Sub-Pillar"] = list(sub_pillars_sorted)
                threatscore_compliance_table["Pillar"] = list(pillars_sorted)
                threatscore_compliance_table["Score"] = list(scores_sorted)
                print(
                    f"\nFramework {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL} Results:"
                )
                print(
                    tabulate(
                        threatscore_compliance_table,
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
