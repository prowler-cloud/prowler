from colorama import Fore, Style

from lib.check.models import Check

# This check has no findings since it is manual


class account_maintain_current_contact_details(Check):
    def execute(self):
        print(
            f"\t{Fore.YELLOW}INFO{Style.RESET_ALL} Manual check: Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Contact Information."
        )
        return []
