from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color


def get_ens_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    marcos = {}
    ens_compliance_table = {
        "Proveedor": [],
        "Marco/Categoria": [],
        "Estado": [],
        "Alto": [],
        "Medio": [],
        "Bajo": [],
        "Opcional": [],
        "Muted": [],
    }
    pass_count = []
    fail_count = []
    muted_count = []
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if compliance.Framework == "ENS":
                for requirement in compliance.Requirements:
                    for attribute in requirement.Attributes:
                        marco_categoria = f"{attribute.Marco}/{attribute.Categoria}"
                        # Check if Marco/Categoria exists
                        if marco_categoria not in marcos:
                            marcos[marco_categoria] = {
                                "Estado": f"{Fore.GREEN}CUMPLE{Style.RESET_ALL}",
                                "Opcional": 0,
                                "Alto": 0,
                                "Medio": 0,
                                "Bajo": 0,
                                "Muted": 0,
                            }
                        if finding.muted:
                            if index not in muted_count:
                                muted_count.append(index)
                                marcos[marco_categoria]["Muted"] += 1
                        else:
                            if finding.status == "FAIL":
                                if (
                                    attribute.Tipo != "recomendacion"
                                    and index not in fail_count
                                ):
                                    fail_count.append(index)
                                    marcos[marco_categoria][
                                        "Estado"
                                    ] = f"{Fore.RED}NO CUMPLE{Style.RESET_ALL}"
                            elif finding.status == "PASS" and index not in pass_count:
                                pass_count.append(index)
                        if attribute.Nivel == "opcional":
                            marcos[marco_categoria]["Opcional"] += 1
                        elif attribute.Nivel == "alto":
                            marcos[marco_categoria]["Alto"] += 1
                        elif attribute.Nivel == "medio":
                            marcos[marco_categoria]["Medio"] += 1
                        elif attribute.Nivel == "bajo":
                            marcos[marco_categoria]["Bajo"] += 1

    # Add results to table
    for marco in sorted(marcos):
        ens_compliance_table["Proveedor"].append(compliance.Provider)
        ens_compliance_table["Marco/Categoria"].append(marco)
        ens_compliance_table["Estado"].append(marcos[marco]["Estado"])
        ens_compliance_table["Opcional"].append(
            f"{Fore.BLUE}{marcos[marco]['Opcional']}{Style.RESET_ALL}"
        )
        ens_compliance_table["Alto"].append(
            f"{Fore.LIGHTRED_EX}{marcos[marco]['Alto']}{Style.RESET_ALL}"
        )
        ens_compliance_table["Medio"].append(
            f"{orange_color}{marcos[marco]['Medio']}{Style.RESET_ALL}"
        )
        ens_compliance_table["Bajo"].append(
            f"{Fore.YELLOW}{marcos[marco]['Bajo']}{Style.RESET_ALL}"
        )
        ens_compliance_table["Muted"].append(
            f"{orange_color}{marcos[marco]['Muted']}{Style.RESET_ALL}"
        )
    if (
        len(fail_count) + len(pass_count) + len(muted_count) > 1
    ):  # If there are no resources, don't print the compliance table
        print(
            f"\nEstado de Cumplimiento de {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL}:"
        )
        total_findings_count = len(fail_count) + len(pass_count) + len(muted_count)
        overview_table = [
            [
                f"{Fore.RED}{round(len(fail_count) / total_findings_count * 100, 2)}% ({len(fail_count)}) NO CUMPLE{Style.RESET_ALL}",
                f"{Fore.GREEN}{round(len(pass_count) / total_findings_count * 100, 2)}% ({len(pass_count)}) CUMPLE{Style.RESET_ALL}",
                f"{orange_color}{round(len(muted_count) / total_findings_count * 100, 2)}% ({len(muted_count)}) MUTED{Style.RESET_ALL}",
            ]
        ]
        print(tabulate(overview_table, tablefmt="rounded_grid"))
        if not compliance_overview:
            print(
                f"\nResultados de {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL}:"
            )
            print(
                tabulate(
                    ens_compliance_table,
                    headers="keys",
                    tablefmt="rounded_grid",
                )
            )
            print(
                f"{Style.BRIGHT}* Solo aparece el Marco/Categoria que contiene resultados.{Style.RESET_ALL}"
            )
            print(f"\nResultados detallados de {compliance_framework.upper()} en:")
            print(
                f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework}.csv\n"
            )
