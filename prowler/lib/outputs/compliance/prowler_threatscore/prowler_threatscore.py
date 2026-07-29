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
    pass_count = set()
    fail_count = set()
    muted_count = set()
    pillars = {}
    pillar_seen = {}
    provider = ""
    generic_score = 0
    max_generic_score = 0
    counted_findings_generic = {}
    score_per_pillar = {}
    max_score_per_pillar = {}
    counted_findings_per_pillar = {}
    audit_config = get_scan_audit_config()
    config_status_cache = {}
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if compliance.Framework == "ProwlerThreatScore":
                provider = compliance.Provider
                for requirement in compliance.Requirements:
                    config_status = resolve_requirement_config_status(
                        requirement, audit_config, config_status_cache
                    )
                    effective_status = get_effective_status(
                        finding.status, config_status
                    )
                    for attribute in requirement.Attributes:
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
                            counted_findings_per_pillar[pillar] = {}

                        # Revoke an earlier PASS score if a later requirement FAILs.
                        if not finding.muted:
                            contribution = attribute.LevelOfRisk * attribute.Weight
                            counted = counted_findings_per_pillar[pillar]
                            if index not in counted:
                                max_score_per_pillar[pillar] += contribution
                                if effective_status == "PASS":
                                    score_per_pillar[pillar] += contribution
                                    counted[index] = contribution
                                else:
                                    counted[index] = 0
                            elif effective_status == "FAIL" and counted[index]:
                                score_per_pillar[pillar] -= counted[index]
                                counted[index] = 0

                        if pillar not in pillars:
                            pillars[pillar] = {"FAIL": 0, "PASS": 0, "Muted": 0}
                            pillar_seen[pillar] = {}

                        status = "Muted" if finding.muted else effective_status
                        accumulate_overview_status(
                            index, status, pass_count, fail_count, muted_count
                        )
                        accumulate_group_status(
                            index, status, pillars[pillar], pillar_seen[pillar]
                        )

                        # Generic score, with the same PASS-revocation on FAIL.
                        if not finding.muted:
                            contribution = attribute.LevelOfRisk * attribute.Weight
                            if index not in counted_findings_generic:
                                max_generic_score += contribution
                                if effective_status == "PASS":
                                    generic_score += contribution
                                    counted_findings_generic[index] = contribution
                                else:
                                    counted_findings_generic[index] = 0
                            elif (
                                effective_status == "FAIL"
                                and counted_findings_generic[index]
                            ):
                                generic_score -= counted_findings_generic[index]
                                counted_findings_generic[index] = 0

    no_findings_pillars = []
    bulk_compliance = (
        Compliance.get_bulk(provider=provider.lower()).get(compliance_framework)
        if provider
        else None
    )
    if bulk_compliance:
        for requirement in bulk_compliance.Requirements:
            for attribute in requirement.Attributes:
                pillar = attribute.Section
                if pillar not in pillars.keys() and pillar not in no_findings_pillars:
                    no_findings_pillars.append(pillar)

    pillars = dict(sorted(pillars.items()))
    for pillar in pillars:
        pillar_table["Provider"].append(provider)
        pillar_table["Pillar"].append(pillar)
        if max_score_per_pillar[pillar] == 0:
            pillar_score = 100.0
            score_color = Fore.GREEN
        else:
            pillar_score = (
                score_per_pillar[pillar] / max_score_per_pillar[pillar]
            ) * 100
            score_color = Fore.RED
        pillar_table["Score"].append(
            f"{Style.BRIGHT}{score_color}{pillar_score:.2f}%{Style.RESET_ALL}"
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

    for pillar in no_findings_pillars:
        pillar_table["Provider"].append(provider)
        pillar_table["Pillar"].append(pillar)
        pillar_table["Score"].append(f"{Style.BRIGHT}{Fore.GREEN}100%{Style.RESET_ALL}")
        pillar_table["Status"].append(f"{Fore.GREEN}PASS{Style.RESET_ALL}")
        pillar_table["Muted"].append(f"{orange_color}0{Style.RESET_ALL}")

    # Sort table by pillars
    pillar_table["Pillar"] = sorted(pillar_table["Pillar"])

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
                # Handle division by zero when all findings are muted
                if max_generic_score == 0:
                    generic_threat_score = 100.0
                else:
                    generic_threat_score = generic_score / max_generic_score * 100
                print(f"\nGeneric Threat Score: {generic_threat_score:.2f}%")
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
