import sys

from colorama import Fore, Style
from tabulate import tabulate

from prowler.lib.logger import logger


def display_compliance_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
):
    try:
        if "ens_rd2022_aws" in compliance_framework:
            marcos = {}
            ens_compliance_table = {
                "Proveedor": [],
                "Marco/Categoria": [],
                "Estado": [],
                "PYTEC": [],
                "Alto": [],
                "Medio": [],
                "Bajo": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                check = bulk_checks_metadata[finding.check_metadata.CheckID]
                check_compliances = check.Compliance
                for compliance in check_compliances:
                    if (
                        compliance.Framework == "ENS"
                        and compliance.Provider == "AWS"
                        and compliance.Version == "RD2022"
                    ):
                        compliance_version = compliance.Version
                        compliance_fm = compliance.Framework
                        compliance_provider = compliance.Provider
                        for requirement in compliance.Requirements:
                            for attribute in requirement.Attributes:
                                marco_categoria = (
                                    f"{attribute['Marco']}/{attribute['Categoria']}"
                                )
                                # Check if Marco/Categoria exists
                                if marco_categoria not in marcos:
                                    marcos[marco_categoria] = {
                                        "Estado": f"{Fore.GREEN}CUMPLE{Style.RESET_ALL}",
                                        "Pytec": 0,
                                        "Alto": 0,
                                        "Medio": 0,
                                        "Bajo": 0,
                                    }
                                if finding.status == "FAIL":
                                    fail_count += 1
                                    marcos[marco_categoria][
                                        "Estado"
                                    ] = f"{Fore.RED}NO CUMPLE{Style.RESET_ALL}"
                                elif finding.status == "PASS":
                                    pass_count += 1
                                if attribute["Nivel"] == "pytec":
                                    marcos[marco_categoria]["Pytec"] += 1
                                elif attribute["Nivel"] == "alto":
                                    marcos[marco_categoria]["Alto"] += 1
                                elif attribute["Nivel"] == "medio":
                                    marcos[marco_categoria]["Medio"] += 1
                                elif attribute["Nivel"] == "bajo":
                                    marcos[marco_categoria]["Bajo"] += 1

            # Add results to table
            for marco in marcos:
                ens_compliance_table["Proveedor"].append("aws")
                ens_compliance_table["Marco/Categoria"].append(marco)
                ens_compliance_table["Estado"].append(marcos[marco]["Estado"])
                ens_compliance_table["PYTEC"].append(
                    f"{Fore.LIGHTRED_EX}{marcos[marco]['Pytec']}{Style.RESET_ALL}"
                )
                ens_compliance_table["Alto"].append(
                    f"{Fore.RED}{marcos[marco]['Alto']}{Style.RESET_ALL}"
                )
                ens_compliance_table["Medio"].append(
                    f"{Fore.YELLOW}{marcos[marco]['Medio']}{Style.RESET_ALL}"
                )
                ens_compliance_table["Bajo"].append(
                    f"{Fore.BLUE}{marcos[marco]['Bajo']}{Style.RESET_ALL}"
                )
            if fail_count + pass_count < 0:
                print(
                    f"\n {Style.BRIGHT}There are no resources for {Fore.YELLOW}{compliance_fm} {compliance_version} - {compliance_provider}{Style.RESET_ALL}.\n"
                )
            else:
                print(
                    f"\nEstado de Cumplimiento de {Fore.YELLOW}{compliance_fm} {compliance_version} - {compliance_provider}{Style.RESET_ALL}:"
                )
                overview_table = [
                    [
                        f"{Fore.RED}{round(fail_count/(fail_count+pass_count)*100, 2)}% ({fail_count}) NO CUMPLE{Style.RESET_ALL}",
                        f"{Fore.GREEN}{round(pass_count/(fail_count+pass_count)*100, 2)}% ({pass_count}) CUMPLE{Style.RESET_ALL}",
                    ]
                ]
                print(tabulate(overview_table, tablefmt="rounded_grid"))
                print(
                    f"\nResultados de {Fore.YELLOW}{compliance_fm} {compliance_version} - {compliance_provider}{Style.RESET_ALL}:"
                )
                print(
                    tabulate(
                        ens_compliance_table, headers="keys", tablefmt="rounded_grid"
                    )
                )
                print(
                    f"{Style.BRIGHT}* Solo aparece el Marco/Categoria que contiene resultados.{Style.RESET_ALL}"
                )
                print("\nResultados detallados en:")
                print(
                    f" - CSV: {output_directory}/{output_filename}_{compliance_framework[0]}.csv\n"
                )
        if "cis" in str(compliance_framework):
            sections = {}
            cis_compliance_table = {
                "Provider": [],
                "Section": [],
                "Level 1": [],
                "Level 2": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                check = bulk_checks_metadata[finding.check_metadata.CheckID]
                check_compliances = check.Compliance
                for compliance in check_compliances:
                    if compliance.Framework == "CIS-AWS" and compliance.Version in str(
                        compliance_framework
                    ):
                        compliance_version = compliance.Version
                        compliance_fm = compliance.Framework
                        for requirement in compliance.Requirements:
                            for attribute in requirement.Attributes:
                                section = attribute["Section"]
                                # Check if Section exists
                                if section not in sections:
                                    sections[section] = {
                                        "Status": f"{Fore.GREEN}PASS{Style.RESET_ALL}",
                                        "Level 1": {"FAIL": 0, "PASS": 0},
                                        "Level 2": {"FAIL": 0, "PASS": 0},
                                    }
                                if finding.status == "FAIL":
                                    fail_count += 1
                                elif finding.status == "PASS":
                                    pass_count += 1
                                if attribute["Profile"] == "Level 1":
                                    if finding.status == "FAIL":
                                        sections[section]["Level 1"]["FAIL"] += 1
                                    else:
                                        sections[section]["Level 1"]["PASS"] += 1
                                elif attribute["Profile"] == "Level 2":
                                    if finding.status == "FAIL":
                                        sections[section]["Level 2"]["FAIL"] += 1
                                    else:
                                        sections[section]["Level 2"]["PASS"] += 1

            # Add results to table
            sections = dict(sorted(sections.items()))
            for section in sections:
                cis_compliance_table["Provider"].append("aws")
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
            if fail_count + pass_count < 0:
                print(
                    f"\n {Style.BRIGHT}There are no resources for {Fore.YELLOW}{compliance_fm}-{compliance_version}{Style.RESET_ALL}.\n"
                )
            else:
                print(
                    f"\nCompliance Status of {Fore.YELLOW}{compliance_fm}-{compliance_version}{Style.RESET_ALL} Framework:"
                )
                overview_table = [
                    [
                        f"{Fore.RED}{round(fail_count/(fail_count+pass_count)*100, 2)}% ({fail_count}) FAIL{Style.RESET_ALL}",
                        f"{Fore.GREEN}{round(pass_count/(fail_count+pass_count)*100, 2)}% ({pass_count}) PASS{Style.RESET_ALL}",
                    ]
                ]
                print(tabulate(overview_table, tablefmt="rounded_grid"))
                print(
                    f"\nFramework {Fore.YELLOW}{compliance_fm}-{compliance_version}{Style.RESET_ALL} Results:"
                )
                print(
                    tabulate(
                        cis_compliance_table, headers="keys", tablefmt="rounded_grid"
                    )
                )
                print(
                    f"{Style.BRIGHT}* Only sections containing results appear.{Style.RESET_ALL}"
                )
                print("\nDetailed Results in:")
                print(
                    f" - CSV: {output_directory}/{output_filename}_{compliance_framework[0]}.csv\n"
                )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
        )
        sys.exit()
