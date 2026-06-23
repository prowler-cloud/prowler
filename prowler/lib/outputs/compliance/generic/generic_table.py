from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color
from prowler.lib.check.compliance_config_eval import (
    get_effective_status,
    get_scan_audit_config,
    resolve_requirement_config_status,
)


def get_generic_compliance_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    pass_count = []
    fail_count = []
    muted_count = []
    audit_config = get_scan_audit_config()
    config_status_cache = {}
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if (
                compliance.Framework.upper()
                in compliance_framework.upper().replace("_", "-")
                and compliance.Version in compliance_framework.upper()
                and compliance.Provider.upper() in compliance_framework.upper()
            ):
                effective_status = finding.status
                for requirement in compliance.Requirements:
                    if finding.check_id in requirement.Checks:
                        config_status = resolve_requirement_config_status(
                            requirement, audit_config, config_status_cache
                        )
                        if (
                            get_effective_status(finding.status, config_status)
                            == "FAIL"
                        ):
                            effective_status = "FAIL"
                            break
                if finding.muted:
                    if index not in muted_count:
                        muted_count.append(index)
                else:
                    if effective_status == "FAIL" and index not in fail_count:
                        fail_count.append(index)
                    elif effective_status == "PASS" and index not in pass_count:
                        pass_count.append(index)
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
            print(f"\nDetailed results of {compliance_framework.upper()} are in:")
            print(
                f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework}.csv\n"
            )
