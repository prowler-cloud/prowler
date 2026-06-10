from colorama import Fore, Style

from prowler.config.config import banner_color, orange_color, prowler_version, timestamp


def print_banner(legend: bool = False, provider: str = None):
    """
    Prints the banner with optional legend for color codes.

    Parameters:
    - legend (bool): Flag to indicate whether to print the color legend or not. Default is False.
    - provider (str): The provider being scanned, used to tailor the Prowler Cloud banner.

    Returns:
    - None
    """
    banner = rf"""{banner_color}                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v{prowler_version}
|_|{Fore.BLUE} Get the most at https://cloud.prowler.com {Style.RESET_ALL}

{Fore.YELLOW}Date: {timestamp.strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}
"""
    print(banner)

    print_prowler_cloud_banner(provider)

    if legend:
        print(
            f"""
{Style.BRIGHT}Color code for results:{Style.RESET_ALL}
- {Fore.YELLOW}MANUAL (Manual check){Style.RESET_ALL}
- {Fore.GREEN}PASS (Recommended value){Style.RESET_ALL}
- {orange_color}MUTED (Muted by muted list){Style.RESET_ALL}
- {Fore.RED}FAIL (Fix required){Style.RESET_ALL}
            """
        )


def print_prowler_cloud_banner(provider: str = None):
    """
    Prints a promotional banner highlighting what Prowler Cloud adds on top of
    the open-source CLI.

    Shown at the start and end of a scan to let users know about the managed
    platform capabilities they are missing (attack paths, AI, organizations,
    continuous scanning, integrations and live compliance dashboards).

    Parameters:
    - provider (str): The provider that was scanned, used to tailor the message.

    Returns:
    - None
    """
    provider_label = f"{provider.upper()} " if provider else ""
    check = f"{Fore.GREEN}✓{Style.RESET_ALL}"
    bar = f"{banner_color}│{Style.RESET_ALL}"
    print(
        f"""
{bar} {Style.BRIGHT}You're getting a snapshot. Prowler Cloud gives you the full picture.{Style.RESET_ALL}
{bar}
{bar} {check} {Style.BRIGHT}Attack Path Visualization{Style.RESET_ALL} - see how attackers chain risks to reach your crown jewels
{bar} {check} {Style.BRIGHT}Lighthouse AI + MCP{Style.RESET_ALL} - autonomous triage, prioritization and remediation
{bar} {check} {Style.BRIGHT}Organizations{Style.RESET_ALL} - all your {provider_label}accounts under one organization
{bar} {check} {Style.BRIGHT}Continuous scanning{Style.RESET_ALL} - scheduled scans with history, trends and alerts
{bar} {check} {Style.BRIGHT}Integrations{Style.RESET_ALL} - Jira, Slack, AWS Security Hub, Amazon S3, SSO and RBAC
{bar} {check} {Style.BRIGHT}Reports{Style.RESET_ALL} - download ready-to-share PDF reports
{bar} {check} {Style.BRIGHT}Live compliance{Style.RESET_ALL} - dashboards for 50+ frameworks, always up to date
{bar}
{bar} {Fore.BLUE}Start free at cloud.prowler.com{Style.RESET_ALL}
"""
    )
