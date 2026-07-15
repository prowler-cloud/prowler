from colorama import Fore, Style

from prowler.config.config import banner_color, orange_color, prowler_version, timestamp
from prowler.lib.cloud_urls import PROWLER_CLI_UTM_SOURCE, build_cloud_signup_url

# Prowler Cloud landing URL used by the CLI banner. The visible text stays
# "cloud.prowler.com" while the clickable target carries the UTM source so
# terminals that support OSC 8 hyperlinks attribute the visit to the CLI.
CLOUD_DISPLAY_TEXT = "cloud.prowler.com"
CLOUD_BANNER_URL = build_cloud_signup_url(PROWLER_CLI_UTM_SOURCE)


def _hyperlink(url: str, text: str) -> str:
    """Wrap ``text`` in an OSC 8 terminal hyperlink pointing to ``url``.

    Terminals that support OSC 8 render ``text`` as a clickable link to ``url``;
    those that do not simply display ``text`` unchanged.
    """
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


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
| .__/|_|  \___/ \_/\_/ |_|\___|_| CLI - v{prowler_version}
|_|

{Fore.YELLOW}Date: {timestamp.strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}
"""
    print(banner)

    print_prowler_cloud_banner(provider)

    if legend:
        print(f"""
{Style.BRIGHT}Color code for results:{Style.RESET_ALL}
- {Fore.YELLOW}MANUAL (Manual check){Style.RESET_ALL}
- {Fore.GREEN}PASS (Recommended value){Style.RESET_ALL}
- {orange_color}MUTED (Muted by muted list){Style.RESET_ALL}
- {Fore.RED}FAIL (Fix required){Style.RESET_ALL}
            """)


def print_prowler_cloud_banner(provider: str = None):
    """
    Prints a promotional banner highlighting what Prowler Cloud adds on top of
    the open-source CLI.

    Shown at the start and end of a scan to let users know about the managed
    platform capabilities they are missing (CLI findings upload, attack paths,
    AI, triage, organizations, continuous scanning with custom scheduling and
    scan configuration, integrations and live compliance dashboards).

    Parameters:
    - provider (str): The provider that was scanned, used to tailor the message.

    Returns:
    - None
    """
    check = f"{Fore.GREEN}✓{Style.RESET_ALL}"
    bar = f"{banner_color}│{Style.RESET_ALL}"
    print(f"""
{bar} {Style.BRIGHT}You're getting a snapshot 📸. Prowler Cloud gives you the full picture:{Style.RESET_ALL}
{bar}
{bar} {check} {Style.BRIGHT}Send your findings{Style.RESET_ALL} - directly from the Prowler CLI to Prowler Cloud.
{bar} {check} {Style.BRIGHT}Continuous Security Monitoring{Style.RESET_ALL} - custom scheduling and scan configuration with history, trends and alerts.
{bar} {check} {Style.BRIGHT}Triage{Style.RESET_ALL} - review findings, flag false positives and track accepted risk with your team.
{bar} {check} {Style.BRIGHT}Lighthouse AI + MCP{Style.RESET_ALL} - autonomous triage, custom dashboards, prioritization with prevention and remediation.
{bar} {check} {Style.BRIGHT}Alerts{Style.RESET_ALL} - get notified when anything you want is happening.
{bar} {check} {Style.BRIGHT}Live Compliance{Style.RESET_ALL} - dashboards for 50+ frameworks, always up to date.
{bar} {check} {Style.BRIGHT}Remediation{Style.RESET_ALL} - complete guided remediation including Autonomous remediation with Lighthouse AI.
{bar} {check} {Style.BRIGHT}Attack Path Visualization{Style.RESET_ALL} - see how attackers chain risks to reach your crown jewels.
{bar} {check} {Style.BRIGHT}Bulk Provisioning{Style.RESET_ALL} - add your entire AWS Organization in seconds.
{bar} {check} {Style.BRIGHT}Integrations{Style.RESET_ALL} - Anything with our MCP + Jira, Slack, AWS Security Hub, Amazon S3, SSO and RBAC.
{bar}
{bar} {banner_color}Start free at 👉 {_hyperlink(CLOUD_BANNER_URL, CLOUD_DISPLAY_TEXT)}{Style.RESET_ALL}
""")
