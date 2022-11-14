from colorama import Fore, Style

from lib.check.models import Check

# This check has no findings since it is manual


class account_security_contact_information_is_registered(Check):
    def execute(self):
        print(
            f"\t{Fore.YELLOW}INFO{Style.RESET_ALL} Manual check: Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Alternate Contacts -> Security Section."
        )
        return []
