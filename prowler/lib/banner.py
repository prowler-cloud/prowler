import os

from colorama import Fore, Style

from prowler.config.config import banner_color, orange_color, prowler_version, timestamp

# Prowler Cloud landing URL used by the CLI banner. The visible text stays
# "cloud.prowler.com" while the clickable target carries the UTM source so
# terminals that support OSC 8 hyperlinks attribute the visit to the CLI.
CLOUD_DISPLAY_TEXT = "cloud.prowler.com"
CLOUD_BANNER_URL = "https://cloud.prowler.com/sign-up?utm_source=prowler-cli"

# Compact hand-off shown by `prowler dashboard`. Same copy, campaign and medium
# as the OSS HTML report CTA and the dashboard Findings page; ``utm_source``
# identifies the terminal. The URL is static: no local paths or findings data.
DASHBOARD_CTA_URL = (
    "https://cloud.prowler.com/sign-up"
    "?utm_source=prowler-dashboard-terminal&utm_medium=oss&utm_campaign=report-handoff"
)

# Set to a non-empty value other than 0/false/no to skip promotional blocks.
NO_PROMOTIONS_ENV = "PROWLER_NO_PROMOTIONS"


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


def promotions_disabled() -> bool:
    """Return True when ``PROWLER_NO_PROMOTIONS`` asks to skip promotional output."""
    value = os.environ.get(NO_PROMOTIONS_ENV, "").strip().lower()
    return value not in ("", "0", "false", "no")


def print_dashboard_banner(csv_directory: str) -> None:
    """
    Prints the compact `prowler dashboard` header: identity, version and the
    directory the CSV files are loaded from. The server URL is announced
    separately once the server is listening.

    Parameters:
    - csv_directory (str): the directory the dashboard reads CSV files from.

    Returns:
    - None
    """
    print(
        f"{Style.BRIGHT}Prowler Local Dashboard \u00b7 v{prowler_version}{Style.RESET_ALL}\n"
        f"Loading CSV files from: {csv_directory}\n"
    )


def print_dashboard_promotion() -> None:
    """
    Prints the single compact Prowler Cloud hand-off block for `prowler dashboard`.
    Skipped when ``PROWLER_NO_PROMOTIONS`` is set. Plain text fits 80 columns and
    the full URL stays on its own line so it can be copied; terminals with OSC 8
    support also get a clickable CTA.

    Returns:
    - None
    """
    if promotions_disabled():
        return
    cta = _hyperlink(DASHBOARD_CTA_URL, "Explore Prowler Cloud")
    print(
        f"{Style.BRIGHT}Keep scanning locally. Bring your findings to Prowler Cloud."
        f"{Style.RESET_ALL}\n"
        "Import your accompanying OCSF report to explore managed security\n"
        "workflows.\n"
        f"{banner_color}{cta}:{Style.RESET_ALL}\n"
        f"{DASHBOARD_CTA_URL}\n"
        "Nothing is uploaded automatically.\n"
    )
