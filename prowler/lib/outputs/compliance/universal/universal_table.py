from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color
from prowler.lib.check.compliance_models import ComplianceFramework


def get_universal_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework_name: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
    framework: ComplianceFramework = None,
    provider: str = None,
    output_formats: list = None,
) -> None:
    """Render a compliance console table driven by TableConfig.

    Supports 3 modes:
    - Grouped: group_by only (generic, C5, CSA, ISO, KISA)
    - Split: group_by + split_by (CIS Level 1/2, ENS alto/medio/bajo/opcional)
    - Scored: group_by + scoring (ThreatScore weighted risk %)

    When ``provider`` is given and ``checks`` is a multi-provider dict,
    only the checks for that provider are matched against findings.
    """
    if framework is None or not framework.outputs or not framework.outputs.table_config:
        return

    tc = framework.outputs.table_config
    labels = tc.labels or _default_labels()

    group_by = tc.group_by
    split_by = tc.split_by
    scoring = tc.scoring

    if scoring:
        _render_scored(
            findings,
            bulk_checks_metadata,
            compliance_framework_name,
            output_filename,
            output_directory,
            compliance_overview,
            framework,
            group_by,
            scoring,
            labels,
            provider,
            output_formats=output_formats,
        )
    elif split_by:
        _render_split(
            findings,
            bulk_checks_metadata,
            compliance_framework_name,
            output_filename,
            output_directory,
            compliance_overview,
            framework,
            group_by,
            split_by,
            labels,
            provider,
            output_formats=output_formats,
        )
    else:
        _render_grouped(
            findings,
            bulk_checks_metadata,
            compliance_framework_name,
            output_filename,
            output_directory,
            compliance_overview,
            framework,
            group_by,
            labels,
            provider,
            output_formats=output_formats,
        )


def _default_labels():
    """Return a simple namespace with default labels."""
    from prowler.lib.check.compliance_models import TableLabels

    return TableLabels()


def _build_requirement_check_map(framework, provider=None):
    """Build a map of check_id -> list of requirements for fast lookup.

    When *provider* is given, only the checks for that provider are included.
    """
    check_map = {}
    for req in framework.requirements:
        checks = req.checks
        if provider:
            all_checks = checks.get(provider.lower(), [])
        else:
            all_checks = []
            for check_list in checks.values():
                all_checks.extend(check_list)
        for check_id in all_checks:
            if check_id not in check_map:
                check_map[check_id] = []
            check_map[check_id].append(req)
    return check_map


def _get_group_key(req, group_by):
    """Extract the group key from a requirement."""
    if group_by == "_Tactics":
        return req.tactics or []
    return [req.attributes.get(group_by, "Unknown")]


def _print_overview(pass_count, fail_count, muted_count, framework_name, labels):
    """Print the overview pass/fail/muted summary."""
    total = len(fail_count) + len(pass_count) + len(muted_count)
    if total < 2:
        return False

    title = (
        labels.title
        or f"Compliance Status of {Fore.YELLOW}{framework_name.upper()}{Style.RESET_ALL} Framework:"
    )
    print(f"\n{title}")

    fail_pct = round(len(fail_count) / total * 100, 2)
    pass_pct = round(len(pass_count) / total * 100, 2)
    muted_pct = round(len(muted_count) / total * 100, 2)

    fail_label = labels.fail_label
    pass_label = labels.pass_label

    overview_table = [
        [
            f"{Fore.RED}{fail_pct}% ({len(fail_count)}) {fail_label}{Style.RESET_ALL}",
            f"{Fore.GREEN}{pass_pct}% ({len(pass_count)}) {pass_label}{Style.RESET_ALL}",
            f"{orange_color}{muted_pct}% ({len(muted_count)}) MUTED{Style.RESET_ALL}",
        ]
    ]
    print(tabulate(overview_table, tablefmt="rounded_grid"))
    return True


def _render_grouped(
    findings,
    bulk_checks_metadata,
    compliance_framework_name,
    output_filename,
    output_directory,
    compliance_overview,
    framework,
    group_by,
    labels,
    provider=None,
    output_formats=None,
):
    """Grouped mode: one row per group with pass/fail counts."""
    check_map = _build_requirement_check_map(framework, provider)
    groups = {}
    pass_count = []
    fail_count = []
    muted_count = []

    for index, finding in enumerate(findings):
        check_id = finding.check_metadata.CheckID
        if check_id not in check_map:
            continue

        for req in check_map[check_id]:
            for group_key in _get_group_key(req, group_by):
                if group_key not in groups:
                    groups[group_key] = {"FAIL": 0, "PASS": 0, "Muted": 0}

                if finding.muted:
                    if index not in muted_count:
                        muted_count.append(index)
                        groups[group_key]["Muted"] += 1
                else:
                    if finding.status == "FAIL" and index not in fail_count:
                        fail_count.append(index)
                        groups[group_key]["FAIL"] += 1
                    elif finding.status == "PASS" and index not in pass_count:
                        pass_count.append(index)
                        groups[group_key]["PASS"] += 1

    if not _print_overview(
        pass_count, fail_count, muted_count, compliance_framework_name, labels
    ):
        return

    if not compliance_overview:
        provider_header = labels.provider_header
        group_header = labels.group_header or group_by
        table = {
            provider_header: [],
            group_header: [],
            labels.status_header: [],
            "Muted": [],
        }
        for group_key in sorted(groups):
            table[provider_header].append(
                framework.provider or (provider.upper() if provider else "")
            )
            table[group_header].append(group_key)
            if groups[group_key]["FAIL"] > 0:
                table[labels.status_header].append(
                    f"{Fore.RED}{labels.fail_label}({groups[group_key]['FAIL']}){Style.RESET_ALL}"
                )
            else:
                table[labels.status_header].append(
                    f"{Fore.GREEN}{labels.pass_label}({groups[group_key]['PASS']}){Style.RESET_ALL}"
                )
            table["Muted"].append(
                f"{orange_color}{groups[group_key]['Muted']}{Style.RESET_ALL}"
            )

        results_title = (
            labels.results_title
            or f"Framework {Fore.YELLOW}{compliance_framework_name.upper()}{Style.RESET_ALL} Results:"
        )
        print(f"\n{results_title}")
        print(tabulate(table, headers="keys", tablefmt="rounded_grid"))
        footer = labels.footer_note or "* Only sections containing results appear."
        print(f"{Style.BRIGHT}{footer}{Style.RESET_ALL}")
        print(f"\nDetailed results of {compliance_framework_name.upper()} are in:")
        print(
            f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework_name}.csv"
        )
        if "json-ocsf" in (output_formats or []):
            print(
                f" - OCSF: {output_directory}/compliance/{output_filename}_{compliance_framework_name}.ocsf.json"
            )
        print()


def _render_split(
    findings,
    bulk_checks_metadata,
    compliance_framework_name,
    output_filename,
    output_directory,
    compliance_overview,
    framework,
    group_by,
    split_by,
    labels,
    provider=None,
    output_formats=None,
):
    """Split mode: one row per group with columns for each split value (e.g. Level 1/Level 2)."""
    check_map = _build_requirement_check_map(framework, provider)
    split_field = split_by.field
    split_values = split_by.values
    groups = {}
    pass_count = []
    fail_count = []
    muted_count = []

    for index, finding in enumerate(findings):
        check_id = finding.check_metadata.CheckID
        if check_id not in check_map:
            continue

        for req in check_map[check_id]:
            for group_key in _get_group_key(req, group_by):
                if group_key not in groups:
                    groups[group_key] = {
                        sv: {"FAIL": 0, "PASS": 0} for sv in split_values
                    }
                    groups[group_key]["Muted"] = 0

                split_val = req.attributes.get(split_field, "")

                if finding.muted:
                    if index not in muted_count:
                        muted_count.append(index)
                        groups[group_key]["Muted"] += 1
                else:
                    if finding.status == "FAIL" and index not in fail_count:
                        fail_count.append(index)
                    elif finding.status == "PASS" and index not in pass_count:
                        pass_count.append(index)

                    for sv in split_values:
                        if sv in str(split_val):
                            if not finding.muted:
                                if finding.status == "FAIL":
                                    groups[group_key][sv]["FAIL"] += 1
                                else:
                                    groups[group_key][sv]["PASS"] += 1

    if not _print_overview(
        pass_count, fail_count, muted_count, compliance_framework_name, labels
    ):
        return

    if not compliance_overview:
        provider_header = labels.provider_header
        group_header = labels.group_header or group_by
        table = {provider_header: [], group_header: []}
        for sv in split_values:
            table[sv] = []
        table["Muted"] = []

        for group_key in sorted(groups):
            table[provider_header].append(
                framework.provider or (provider.upper() if provider else "")
            )
            table[group_header].append(group_key)
            for sv in split_values:
                if groups[group_key][sv]["FAIL"] > 0:
                    table[sv].append(
                        f"{Fore.RED}{labels.fail_label}({groups[group_key][sv]['FAIL']}){Style.RESET_ALL}"
                    )
                else:
                    table[sv].append(
                        f"{Fore.GREEN}{labels.pass_label}({groups[group_key][sv]['PASS']}){Style.RESET_ALL}"
                    )
            table["Muted"].append(
                f"{orange_color}{groups[group_key]['Muted']}{Style.RESET_ALL}"
            )

        results_title = (
            labels.results_title
            or f"Framework {Fore.YELLOW}{compliance_framework_name.upper()}{Style.RESET_ALL} Results:"
        )
        print(f"\n{results_title}")
        print(tabulate(table, headers="keys", tablefmt="rounded_grid"))
        footer = labels.footer_note or "* Only sections containing results appear."
        print(f"{Style.BRIGHT}{footer}{Style.RESET_ALL}")
        print(f"\nDetailed results of {compliance_framework_name.upper()} are in:")
        print(
            f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework_name}.csv"
        )
        if "json-ocsf" in (output_formats or []):
            print(
                f" - OCSF: {output_directory}/compliance/{output_filename}_{compliance_framework_name}.ocsf.json"
            )
        print()


def _render_scored(
    findings,
    bulk_checks_metadata,
    compliance_framework_name,
    output_filename,
    output_directory,
    compliance_overview,
    framework,
    group_by,
    scoring,
    labels,
    provider=None,
    output_formats=None,
):
    """Scored mode: weighted risk scoring per group (e.g. ThreatScore)."""
    check_map = _build_requirement_check_map(framework, provider)
    risk_field = scoring.risk_field
    weight_field = scoring.weight_field
    groups = {}
    pass_count = []
    fail_count = []
    muted_count = []

    score_per_group = {}
    max_score_per_group = {}
    counted_per_group = {}
    generic_score = 0
    max_generic_score = 0
    counted_generic = []

    for index, finding in enumerate(findings):
        check_id = finding.check_metadata.CheckID
        if check_id not in check_map:
            continue

        for req in check_map[check_id]:
            for group_key in _get_group_key(req, group_by):
                attrs = req.attributes
                risk = attrs.get(risk_field, 0)
                weight = attrs.get(weight_field, 0)

                if group_key not in groups:
                    groups[group_key] = {"FAIL": 0, "PASS": 0, "Muted": 0}
                    score_per_group[group_key] = 0
                    max_score_per_group[group_key] = 0
                    counted_per_group[group_key] = []

                if index not in counted_per_group[group_key] and not finding.muted:
                    if finding.status == "PASS":
                        score_per_group[group_key] += risk * weight
                    max_score_per_group[group_key] += risk * weight
                    counted_per_group[group_key].append(index)

                if finding.muted:
                    if index not in muted_count:
                        muted_count.append(index)
                        groups[group_key]["Muted"] += 1
                else:
                    if finding.status == "FAIL" and index not in fail_count:
                        fail_count.append(index)
                        groups[group_key]["FAIL"] += 1
                    elif finding.status == "PASS" and index not in pass_count:
                        pass_count.append(index)
                        groups[group_key]["PASS"] += 1

                if index not in counted_generic and not finding.muted:
                    if finding.status == "PASS":
                        generic_score += risk * weight
                    max_generic_score += risk * weight
                    counted_generic.append(index)

    if not _print_overview(
        pass_count, fail_count, muted_count, compliance_framework_name, labels
    ):
        return

    if not compliance_overview:
        provider_header = labels.provider_header
        group_header = labels.group_header or group_by
        table = {
            provider_header: [],
            group_header: [],
            labels.status_header: [],
            "Score": [],
            "Muted": [],
        }

        for group_key in sorted(groups):
            table[provider_header].append(
                framework.provider or (provider.upper() if provider else "")
            )
            table[group_header].append(group_key)
            if max_score_per_group[group_key] == 0:
                group_score = 100.0
                score_color = Fore.GREEN
            else:
                group_score = (
                    score_per_group[group_key] / max_score_per_group[group_key]
                ) * 100
                score_color = Fore.RED
            table["Score"].append(
                f"{Style.BRIGHT}{score_color}{group_score:.2f}%{Style.RESET_ALL}"
            )
            if groups[group_key]["FAIL"] > 0:
                table[labels.status_header].append(
                    f"{Fore.RED}{labels.fail_label}({groups[group_key]['FAIL']}){Style.RESET_ALL}"
                )
            else:
                table[labels.status_header].append(
                    f"{Fore.GREEN}{labels.pass_label}({groups[group_key]['PASS']}){Style.RESET_ALL}"
                )
            table["Muted"].append(
                f"{orange_color}{groups[group_key]['Muted']}{Style.RESET_ALL}"
            )

        if max_generic_score == 0:
            generic_threat_score = 100.0
        else:
            generic_threat_score = generic_score / max_generic_score * 100

        results_title = (
            labels.results_title
            or f"Framework {Fore.YELLOW}{compliance_framework_name.upper()}{Style.RESET_ALL} Results:"
        )
        print(f"\n{results_title}")
        print(f"\nGeneric Threat Score: {generic_threat_score:.2f}%")
        print(tabulate(table, headers="keys", tablefmt="rounded_grid"))
        footer = labels.footer_note or (
            f"{Style.BRIGHT}\n=== Threat Score Guide ===\n"
            f"The lower the score, the higher the risk.{Style.RESET_ALL}\n"
            f"{Style.BRIGHT}(Only sections containing results appear, the score is calculated as the sum of the "
            f"level of risk * weight of the passed findings divided by the sum of the risk * weight of all the findings){Style.RESET_ALL}"
        )
        print(footer)
        print(f"\nDetailed results of {compliance_framework_name.upper()} are in:")
        print(
            f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework_name}.csv"
        )
        if "json-ocsf" in (output_formats or []):
            print(
                f" - OCSF: {output_directory}/compliance/{output_filename}_{compliance_framework_name}.ocsf.json"
            )
        print()
