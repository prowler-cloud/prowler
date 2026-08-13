from colorama import Fore, Style

from prowler.config.config import banner_color, orange_color, prowler_version, timestamp

# Prowler Cloud landing URL used by the CLI banner. The visible text stays
# "cloud.prowler.com" while the clickable target carries the UTM parameters so
# terminals that support OSC 8 hyperlinks attribute the visit to the v3 CLI.
CLOUD_DISPLAY_TEXT = "cloud.prowler.com"
CLOUD_BANNER_URL = (
    "https://cloud.prowler.com/sign-up?utm_source=prowler-cli&utm_content=v3"
)


def _hyperlink(url, text):
    """Wrap ``text`` in an OSC 8 terminal hyperlink pointing to ``url``.

    Terminals that support OSC 8 render ``text`` as a clickable link to ``url``;
    those that do not simply display ``text`` unchanged.
    """
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def print_update_notice(latest_version):
    """
    Prints a notice that a newer Prowler version is available.

    Parameters:
    - latest_version (str): The latest released Prowler version.

    Returns:
    - None
    """
    print(
        f"\n{Fore.YELLOW}A new version of Prowler is available: {prowler_version} → {latest_version}{Style.RESET_ALL}\n"
        f"Upgrading from Prowler v3 is a major version upgrade — see the release notes at\n"
        f"https://github.com/prowler-cloud/prowler/releases before upgrading.\n"
        f"Upgrade with: {Style.BRIGHT}pipx upgrade prowler{Style.RESET_ALL} "
        f"(disable this check with PROWLER_NO_VERSION_CHECK=1)"
    )


def print_prowler_cloud_banner():
    """
    Prints a promotional banner highlighting what Prowler Cloud adds on top of
    the open-source CLI.

    Shown at the end of a scan to let users know about the managed platform
    capabilities they are missing.

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


def print_banner(args):
    banner = rf"""{banner_color}                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v{prowler_version}
|_|{Fore.BLUE} the handy cloud security tool

{Fore.YELLOW}Date: {timestamp.strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}
"""
    print(banner)

    if args.verbose or args.quiet:
        print(
            f"""
Color code for results:
- {Fore.YELLOW}INFO (Information){Style.RESET_ALL}
- {Fore.GREEN}PASS (Recommended value){Style.RESET_ALL}
- {orange_color}WARNING (Ignored by allowlist){Style.RESET_ALL}
- {Fore.RED}FAIL (Fix required){Style.RESET_ALL}
            """
        )
