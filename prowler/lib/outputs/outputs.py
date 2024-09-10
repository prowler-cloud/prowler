from colorama import Fore, Style

from prowler.config.config import orange_color
from prowler.lib.logger import logger
from prowler.lib.persistence import mklist


class GeneratedOutputs:

    def __init__(self, output_bucket=None, output_bucket_no_assume: None = None):
        self._store = True if output_bucket or output_bucket_no_assume else False
        self.regular = mklist() if self._store else None
        self.compliance = mklist() if self._store else None

    def add_compliance(self, compliance):

        if not self._store:
            return

        if cmp:
            self.compliance.append(cmp)

    def add_regular(self, regular):

        if not self._store:
            return

        if rg:
            self.regular.append(rg)

    def make_output(self) -> dict:
        return {"regular": self.regular, "compliance": self.compliance}


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


# TODO: Only pass check_findings, provider.output_options and provider.type
def report(check_findings, provider):
    try:
        output_options = provider.output_options
        if check_findings:
            # TO-DO Generic Function
            if provider.type == "aws":
                check_findings.sort(key=lambda x: x.region)

            if provider.type == "azure":
                check_findings.sort(key=lambda x: x.subscription)

            for finding in check_findings:
                # Print findings by stdout
                color = set_report_color(finding.status, finding.muted)
                stdout_report(
                    finding,
                    color,
                    output_options.verbose,
                    output_options.status,
                    output_options.fixer,
                )

        else:  # No service resources in the whole account
            color = set_report_color("MANUAL")
            if output_options.verbose:
                print(f"\t{color}INFO{Style.RESET_ALL} There are no resources")
        # Separator between findings and bar
        if output_options.verbose:
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
        "total_fail": 0,
        "resources_count": 0,
        "findings_count": 0,
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

    for finding in findings:
        # Save the resource_id
        resources.add(finding.resource_id)

        if finding.status == "PASS":
            total_pass += 1
            findings_count += 1
            if finding.muted is True:
                muted_pass += 1

        if finding.status == "FAIL":
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
    stats["all_fails_are_muted"] = all_fails_are_muted

    return stats
