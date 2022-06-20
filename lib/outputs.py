from colorama import Fore, Style


def report(check_findings):
    check_findings.sort(key=lambda x: x.region)
    for finding in check_findings:
        color = set_report_color(finding.status)
        print(
            f"{color}{finding.status}{Style.RESET_ALL} {finding.region}: {finding.result_extended}"
        )


def set_report_color(status):
    color = ""
    if status == "PASS":
        color = Fore.GREEN
    elif status == "FAIL":
        color = Fore.RED
    elif status == "ERROR":
        color = Fore.BLACK
    elif status == "WARNING":
        color = Fore.YELLOW
    else:
        raise Exception("Invalid Report Status. Must be PASS, FAIL, ERROR or WARNING")
    return color
