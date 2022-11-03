from colorama import Fore, Style

from lib.check.models import Check

### This check has no findings since it is manual


class account_security_questions_are_registered_in_the_aws_account(Check):
    def execute(self):
        print(
            f"\t{Fore.YELLOW}INFO{Style.RESET_ALL} Manual check: Login to the AWS Console as root. Choose your account name on the top right of the window -> My Account -> Configure Security Challenge Questions."
        )
        return []
