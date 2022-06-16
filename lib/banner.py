from colorama import Fore, Style

from config.config import prowler_version, timestamp


def print_version():
    print(f"Prowler {prowler_version}")


def print_banner():
    banner = f"""{Fore.CYAN}                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v{prowler_version}
|_|{Fore.BLUE} the handy cloud security tool
{Fore.YELLOW} Date: {timestamp}{Style.RESET_ALL}
"""
    print(banner)
