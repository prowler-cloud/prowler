from colorama import Fore, Style

from prowler.config.config import orange_color
from prowler.lib.logger import logger


def stdout_report(finding, color, verbose, status, fix):
    if finding.check_metadata.Provider == "aws":
        details = finding.region
    if finding.check_metadata.Provider == "azure":
        details = finding.location
    if finding.check_metadata.Provider == "gcp":
        details = finding.location.lower()
    if finding.check_metadata.Provider == "kubernetes":
        details = finding.namespace.lower()

    if (verbose or fix) and (not status or finding.status in status):
        if finding.muted:
            print(
                f"\t{color}MUTED ({finding.status}){Style.RESET_ALL} {details}: {finding.status_extended}"
            )
        else:
            print(
                f"\t{color}{finding.status}{Style.RESET_ALL} {details}: {finding.status_extended}"
            )


# TODO: Only pass check_findings, output_options and provider.type
def report(check_findings, provider, output_options):
    try:
        verbose = False
        if hasattr(output_options, "verbose"):
            verbose = output_options.verbose
        if check_findings:
            # TO-DO Generic Function
            if provider.type == "aws":
                check_findings.sort(key=lambda x: x.region)

            if provider.type == "azure":
                check_findings.sort(key=lambda x: x.subscription)

            for finding in check_findings:
                # Print findings by stdout
                status = []
                if hasattr(output_options, "status"):
                    status = output_options.status
                fixer = False
                if hasattr(output_options, "fixer"):
                    fixer = output_options.fixer
                color = set_report_color(finding.status, finding.muted)
                stdout_report(
                    finding,
                    color,
                    verbose,
                    status,
                    fixer,
                )

        else:  # No service resources in the whole account
            color = set_report_color("MANUAL")
            if verbose:
                print(f"\t{color}INFO{Style.RESET_ALL} There are no resources")
        # Separator between findings and bar
        if verbose:
            print()
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def set_report_color(status: str, muted: bool = False) -> str:
    """Return the color for a give result status"""
    color = ""
    if muted:
        color = orange_color
    elif status == "PASS":
        color = Fore.GREEN
    elif status == "FAIL":
        color = Fore.RED
    elif status == "MANUAL":
        color = Fore.YELLOW
    else:
        raise Exception("Invalid Report Status. Must be PASS, FAIL or MANUAL.")
    return color


def extract_findings_statistics(findings: list) -> dict:
    """
    extract_findings_statistics takes a list of findings and returns the following dict with the aggregated statistics
    {
        "total_pass": 0,
        "total_muted_pass": 0,
        "total_fail": 0,
        "total_muted_fail": 0,
        "resources_count": 0,
        "findings_count": 0,
        "critical_failed_findings": [],
        "critical_passed_findings": []
        "all_fails_are_muted": False
    }
    """
    logger.info("Extracting audit statistics...")
    stats = {}
    total_pass = 0
    total_fail = 0
    muted_pass = 0
    muted_fail = 0
    resources = set()
    findings_count = 0
    all_fails_are_muted = True
    critical_severity_pass = 0
    critical_severity_fail = 0
    high_severity_pass = 0
    high_severity_fail = 0
    medium_severity_pass = 0
    medium_severity_fail = 0
    low_severity_pass = 0
    low_severity_fail = 0

    for finding in findings:
        # Save the resource_id
        resources.add(finding.resource_id)

        if finding.status == "PASS":
            if finding.check_metadata.Severity == "critical":
                critical_severity_pass += 1
            if finding.check_metadata.Severity == "high":
                high_severity_pass += 1
            if finding.check_metadata.Severity == "medium":
                medium_severity_pass += 1
            if finding.check_metadata.Severity == "low":
                low_severity_pass += 1
            total_pass += 1
            findings_count += 1
            if finding.muted is True:
                muted_pass += 1

        if finding.status == "FAIL":
            if finding.check_metadata.Severity == "critical":
                critical_severity_fail += 1
            if finding.check_metadata.Severity == "high":
                high_severity_fail += 1
            if finding.check_metadata.Severity == "medium":
                medium_severity_fail += 1
            if finding.check_metadata.Severity == "low":
                low_severity_fail += 1
            total_fail += 1
            findings_count += 1
            if finding.muted is True:
                muted_fail += 1
            if not finding.muted and all_fails_are_muted:
                all_fails_are_muted = False

    stats["total_pass"] = total_pass
    stats["total_muted_pass"] = muted_pass
    stats["total_fail"] = total_fail
    stats["total_muted_fail"] = muted_fail
    stats["resources_count"] = len(resources)
    stats["findings_count"] = findings_count
    stats["total_critical_severity_fail"] = critical_severity_fail
    stats["total_critical_severity_pass"] = critical_severity_pass
    stats["total_high_severity_fail"] = high_severity_fail
    stats["total_high_severity_pass"] = high_severity_pass
    stats["total_medium_severity_fail"] = medium_severity_fail
    stats["total_medium_severity_pass"] = medium_severity_pass
    stats["total_low_severity_fail"] = medium_severity_fail
    stats["total_low_severity_pass"] = medium_severity_pass
    stats["all_fails_are_muted"] = all_fails_are_muted

    return stats
