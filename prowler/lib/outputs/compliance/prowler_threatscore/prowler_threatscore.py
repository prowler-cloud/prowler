from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color
from prowler.lib.check.compliance_models import Compliance


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
        "Score": [],
        "Muted": [],
    }
    pass_count = []
    fail_count = []
    muted_count = []
    pillars = {}
    score_per_pillar = {}
    max_score_per_pillar = {}
    counted_findings_per_pillar = {}
    generic_score = 0
    generic_max_score = 0
    generic_counted_findings = []
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if compliance.Framework == "ProwlerThreatScore":
                for requirement in compliance.Requirements:
                    for attribute in requirement.Attributes:
                        # Score per pillar logic
                        pillar = attribute.Section

                        if not any(
                            [
                                pillar in score_per_pillar.keys(),
                                pillar in max_score_per_pillar.keys(),
                                pillar in counted_findings_per_pillar.keys(),
                            ]
                        ):
                            score_per_pillar[pillar] = 0
                            max_score_per_pillar[pillar] = 0
                            counted_findings_per_pillar[pillar] = []

                        if (
                            index not in counted_findings_per_pillar.get(pillar, [])
                            and not finding.muted
                        ):
                            if finding.status == "PASS":
                                score_per_pillar[pillar] += (
                                    attribute.LevelOfRisk * attribute.Weight
                                )
                            max_score_per_pillar[pillar] += (
                                attribute.LevelOfRisk * attribute.Weight
                            )
                            counted_findings_per_pillar[pillar].append(index)

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

                        # Generic score logic
                        if index not in generic_counted_findings and not finding.muted:
                            if finding.status == "PASS":
                                generic_score += (
                                    attribute.LevelOfRisk * attribute.Weight
                                )
                            generic_max_score += (
                                attribute.LevelOfRisk * attribute.Weight
                            )
                            generic_counted_findings.append(index)

    pillars = dict(sorted(pillars.items()))
    for pillar in pillars:
        pillar_table["Provider"].append(compliance.Provider)
        pillar_table["Pillar"].append(pillar)
        pillar_table["Score"].append(
            f"{Style.BRIGHT}{Fore.RED}{(score_per_pillar[pillar] / max_score_per_pillar[pillar]) * 100:.2f}%{Style.RESET_ALL}"
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

    # Add pillars with no findings to the table with Status: PASS and Score: 100%
    provider_name = compliance_framework.split("_")[-1]
    bulk_compliance_frameworks = Compliance.get_bulk(provider_name)

    unique_sections = set()
    for compliance_name, compliance in bulk_compliance_frameworks.items():
        if compliance_name.startswith(f"prowler_threatscore_{provider_name}"):
            for requirement in compliance.Requirements:
                for attribute in requirement.Attributes:
                    unique_sections.add(attribute.Section)

    for section in unique_sections:
        if section not in pillars:
            pillar_table["Provider"].append(provider_name.capitalize())
            pillar_table["Pillar"].append(section)
            pillar_table["Score"].append(
                f"{Style.BRIGHT}{Fore.GREEN}100.00%{Style.RESET_ALL}"
            )
            pillar_table["Status"].append(f"{Fore.GREEN}PASS(0){Style.RESET_ALL}")
            pillar_table["Muted"].append(f"{orange_color}0{Style.RESET_ALL}")

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
                f"\n{Style.BRIGHT}Overall ThreatScore: {generic_score / generic_max_score * 100:.2f}%{Style.RESET_ALL}"
            )
            if len(fail_count) > 0 and len(pillar_table["Pillar"]) > 0:
                print(
                    f"Framework {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL} Results:"
                )

                print(
                    tabulate(
                        pillar_table,
                        tablefmt="rounded_grid",
                        headers="keys",
                    )
                )

                print(
                    f"{Style.BRIGHT}\n=== Threat Score Guide ===\nThe lower the score, the higher the risk.{Style.RESET_ALL}"
                )
                print(
                    f"{Style.BRIGHT}(Only sections containing results appear, the score is calculated as the sum of the level of risk * weight of the passed findings divided by the sum of the risk * weight of all the findings){Style.RESET_ALL}"
                )
                print(f"\nDetailed results of {compliance_framework.upper()} are in:")
                print(
                    f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework}.csv\n"
                )
