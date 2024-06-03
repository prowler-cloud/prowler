from colorama import Fore, Style

from prowler.config.config import banner_color, orange_color, prowler_version, timestamp


def print_banner(legend: bool = False):
    """
    Prints the banner with optional legend for color codes.

    Parameters:
    - legend (bool): Flag to indicate whether to print the color legend or not. Default is False.

    Returns:
    - None
    """
    banner = rf"""{banner_color}                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v{prowler_version}
|_|{Fore.BLUE} the handy multi-cloud security tool

{Fore.YELLOW}Date: {timestamp.strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}
"""
    print(banner)

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
