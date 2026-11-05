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


def _logo_banner(label: str) -> str:
    """Return the Prowler ASCII logo with ``label - v<version>`` and the date line."""
    return rf"""{banner_color}                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_| {label} - v{prowler_version}
|_|

{Fore.YELLOW}Date: {timestamp.strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}
"""


def print_banner(legend: bool = False, provider: str = None):
    """
    Prints the banner with optional legend for color codes.

    Parameters:
    - legend (bool): Flag to indicate whether to print the color legend or not. Default is False.
    - provider (str): The provider being scanned, used to tailor the Prowler Cloud banner.

    Returns:
    - None
    """
    print(_logo_banner("CLI"))

    print_prowler_cloud_banner(provider)

    if legend:
        print(f"""
{Style.BRIGHT}Color code for results:{Style.RESET_ALL}
- {Fore.YELLOW}MANUAL (Manual check){Style.RESET_ALL}
- {Fore.GREEN}PASS (Recommended value){Style.RESET_ALL}
- {orange_color}MUTED (Muted by muted list){Style.RESET_ALL}
- {Fore.RED}FAIL (Fix required){Style.RESET_ALL}
            """)


# Per-provider wording for the bulk onboarding line of the CLI banner.
_BULK_ONBOARDING = {
    "aws": "connect your whole AWS Organization in minutes",
    "azure": "connect every Azure subscription in minutes",
    "gcp": "connect every GCP project in minutes",
    "kubernetes": "connect all your clusters in minutes",
    "m365": "connect every M365 tenant in minutes",
}


def print_prowler_cloud_banner(provider: str = None):
    """
    Prints the Prowler Cloud hand-off shown at the start and end of a CLI scan:
    what the managed platform adds on top of this local snapshot, in six
    short lines that fit an 80-column terminal, plus the sign-up link.
    Skipped when ``PROWLER_NO_PROMOTIONS`` is set.

    Parameters:
    - provider (str): The provider being scanned, used to tailor the onboarding line.

    Returns:
    - None
    """
    if promotions_disabled():
        return
    check = f"{Fore.GREEN}✓{Style.RESET_ALL}"
    bar = f"{banner_color}│{Style.RESET_ALL}"
    onboarding = _BULK_ONBOARDING.get(
        provider, "connect all your accounts and keep them scanned"
    )

    def line(title, text):
        return f"{bar} {check} {Style.BRIGHT}{title}{Style.RESET_ALL} - {text}"

    print(f"""
{bar} {Style.BRIGHT}This scan is a snapshot 📸. Prowler Cloud gives you the full picture.{Style.RESET_ALL}
{bar} Import this scan's OCSF report or scan continuously, with managed workflows.
{bar}
{line("Exploitable Issues", "findings chained into attack paths, with the fix.")}
{line("Findings Triage", "history, trends, false positives and accepted risk.")}
{line("Lighthouse AI + MCP", "ask, prioritize and remediate from your AI tools.")}
{line("Live Compliance", "50+ frameworks across providers and accounts.")}
{line("Alerts & Integrations", "Jira, Slack, Security Hub, S3, SSO and RBAC.")}
{line("Scheduled Scans", onboarding + ".")}
{bar}
{bar} {banner_color}Start free at 👉 {_hyperlink(CLOUD_BANNER_URL, CLOUD_DISPLAY_TEXT)}{Style.RESET_ALL}
{bar} Nothing is uploaded automatically.
""")


def promotions_disabled() -> bool:
    """Return True when ``PROWLER_NO_PROMOTIONS`` asks to skip promotional output."""
    value = os.environ.get(NO_PROMOTIONS_ENV, "").strip().lower()
    return value not in ("", "0", "false", "no")


def print_dashboard_banner() -> None:
    """
    Prints the `prowler dashboard` header: the Prowler logo labelled
    ``Local Dashboard - v<version>`` and the date. The CSV directory and the
    server URL are announced separately.

    Returns:
    - None
    """
    print(_logo_banner("Local Dashboard"))


def print_dashboard_loading(csv_directory: str) -> None:
    """
    Prints the directory the dashboard loads its CSV files from. Shown after the
    hand-off block, right before the files are read.

    Parameters:
    - csv_directory (str): the directory the dashboard reads CSV files from.

    Returns:
    - None
    """
    print(f"{Fore.GREEN}Loading CSV files from {csv_directory} ...{Style.RESET_ALL}")


def print_dashboard_promotion() -> None:
    """
    Prints the single compact Prowler Cloud hand-off block for `prowler dashboard`,
    styled like the CLI's Prowler Cloud banner (bar, bold title, check and 👉 link).
    Skipped when ``PROWLER_NO_PROMOTIONS`` is set. The link shows ``cloud.prowler.com``
    like the CLI banner; terminals with OSC 8 support make it clickable with the
    UTM-tagged URL, others display the plain domain.

    Returns:
    - None
    """
    if promotions_disabled():
        return
    bar = f"{banner_color}│{Style.RESET_ALL}"
    check = f"{Fore.GREEN}✓{Style.RESET_ALL}"
    cta = _hyperlink(DASHBOARD_CTA_URL, CLOUD_DISPLAY_TEXT)
    print(f"""
{bar} {Style.BRIGHT}Keep scanning locally. Bring your findings to Prowler Cloud.{Style.RESET_ALL}
{bar} Import your accompanying OCSF report to explore managed security workflows.
{bar}
{bar} {check} {Style.BRIGHT}Explore Prowler Cloud{Style.RESET_ALL} 👉 {banner_color}{cta}{Style.RESET_ALL}
{bar}
{bar} Nothing is uploaded automatically.
""")
