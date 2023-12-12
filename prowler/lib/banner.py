from colorama import Fore, Style

from prowler.config.config import banner_color, orange_color, prowler_version, timestamp


def print_banner(args):
    banner = f"""{banner_color}                         _
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
