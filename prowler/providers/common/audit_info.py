import sys

from arnparse import arnparse
from boto3 import client, session
from colorama import Fore, Style

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import AWS_Provider, assume_role
from prowler.providers.aws.lib.arn.arn import arn_parsing
from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.lib.audit_info.models import (
    AWS_Audit_Info,
    AWS_Credentials,
    AWS_Organizations_Info,
)
from prowler.providers.azure.azure_provider import Azure_Provider
from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info


class Audit_Info:
    def __init__(self):
        logger.info("Setting Audit Info ...")

    def validate_credentials(self, validate_session: session) -> dict:
        try:
            validate_credentials_client = validate_session.client("sts")
            caller_identity = validate_credentials_client.get_caller_identity()
        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            sys.exit()
        else:
            return caller_identity

    def print_audit_credentials(self, audit_info: AWS_Audit_Info):
        # Beautify audited regions, set "all" if there is no filter region
        regions = (
            ", ".join(audit_info.audited_regions)
            if audit_info.audited_regions is not None
            else "all"
        )
        # Beautify audited profile, set "default" if there is no profile set
        profile = audit_info.profile if audit_info.profile is not None else "default"

        report = f"""
This report is being generated using credentials below:

AWS-CLI Profile: {Fore.YELLOW}[{profile}]{Style.RESET_ALL} AWS Filter Region: {Fore.YELLOW}[{regions}]{Style.RESET_ALL}
AWS Account: {Fore.YELLOW}[{audit_info.audited_account}]{Style.RESET_ALL} UserId: {Fore.YELLOW}[{audit_info.audited_user_id}]{Style.RESET_ALL}
Caller Identity ARN: {Fore.YELLOW}[{audit_info.audited_identity_arn}]{Style.RESET_ALL}
"""
        # If -A is set, print Assumed Role ARN
        if audit_info.assumed_role_info.role_arn is not None:
            report += f"""Assumed Role ARN: {Fore.YELLOW}[{audit_info.assumed_role_info.role_arn}]{Style.RESET_ALL}
"""
        print(report)

    def get_organizations_metadata(
        self, metadata_account: str, assumed_credentials: dict
    ) -> AWS_Organizations_Info:
        try:
            organizations_client = client(
                "organizations",
                aws_access_key_id=assumed_credentials["Credentials"]["AccessKeyId"],
                aws_secret_access_key=assumed_credentials["Credentials"][
                    "SecretAccessKey"
                ],
                aws_session_token=assumed_credentials["Credentials"]["SessionToken"],
            )
            organizations_metadata = organizations_client.describe_account(
                AccountId=metadata_account
            )
            list_tags_for_resource = organizations_client.list_tags_for_resource(
                ResourceId=metadata_account
            )
        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            sys.exit()
        else:
            # Convert Tags dictionary to String
            account_details_tags = ""
            for tag in list_tags_for_resource["Tags"]:
                account_details_tags += tag["Key"] + ":" + tag["Value"] + ","
            organizations_info = AWS_Organizations_Info(
                account_details_email=organizations_metadata["Account"]["Email"],
                account_details_name=organizations_metadata["Account"]["Name"],
                account_details_arn=organizations_metadata["Account"]["Arn"],
                account_details_org=organizations_metadata["Account"]["Arn"].split("/")[
                    1
                ],
                account_details_tags=account_details_tags,
            )
            return organizations_info

    def set_aws_audit_info(self, arguments) -> AWS_Audit_Info:
        """
        set_aws_audit_info returns the AWS_Audit_Info
        """
        logger.info("Setting Azure session ...")

        # Assume Role Options
        input_role = arguments.get("role")
        input_session_duration = arguments.get("session_duration")
        input_external_id = arguments.get("external_id")
        # Since the range(i,j) goes from i to j-1 we have to j+1
        if input_session_duration and input_session_duration not in range(900, 43201):
            raise Exception("Value for -T option must be between 900 and 43200")

        if (
            input_session_duration and input_session_duration != 3600
        ) or input_external_id:
            if not input_role:
                raise Exception("To use -I/-T options -R option is needed")

        input_profile = arguments.get("profile")
        input_regions = arguments.get("region")
        organizations_role_arn = arguments.get("organizations_role")

        # Assumed AWS session
        assumed_session = None

        # Setting session
        current_audit_info.profile = input_profile
        current_audit_info.audited_regions = input_regions

        logger.info("Generating original session ...")
        # Create an global original session using only profile/basic credentials info
        current_audit_info.original_session = AWS_Provider(
            current_audit_info
        ).get_session()
        logger.info("Validating credentials ...")
        # Verificate if we have valid credentials
        caller_identity = self.validate_credentials(current_audit_info.original_session)

        logger.info("Credentials validated")
        logger.info(f"Original caller identity UserId : {caller_identity['UserId']}")
        logger.info(f"Original caller identity ARN : {caller_identity['Arn']}")

        current_audit_info.audited_account = caller_identity["Account"]
        current_audit_info.audited_identity_arn = caller_identity["Arn"]
        current_audit_info.audited_user_id = caller_identity["UserId"]
        current_audit_info.audited_partition = arnparse(
            caller_identity["Arn"]
        ).partition

        logger.info("Checking if organizations role assumption is needed ...")
        if organizations_role_arn:
            current_audit_info.assumed_role_info.role_arn = organizations_role_arn
            current_audit_info.assumed_role_info.session_duration = (
                input_session_duration
            )

            # Check if role arn is valid
            try:
                # this returns the arn already parsed, calls arnparse, into a dict to be used when it is needed to access its fields
                role_arn_parsed = arn_parsing(
                    current_audit_info.assumed_role_info.role_arn
                )

            except Exception as error:
                logger.critical(f"{error.__class__.__name__} -- {error}")
                sys.exit()

            else:
                logger.info(
                    f"Getting organizations metadata for account {organizations_role_arn}"
                )
                assumed_credentials = assume_role(current_audit_info)
                current_audit_info.organizations_metadata = (
                    self.get_organizations_metadata(
                        current_audit_info.audited_account, assumed_credentials
                    )
                )
                logger.info("Organizations metadata retrieved")

        logger.info("Checking if role assumption is needed ...")
        if input_role:
            current_audit_info.assumed_role_info.role_arn = input_role
            current_audit_info.assumed_role_info.session_duration = (
                input_session_duration
            )
            current_audit_info.assumed_role_info.external_id = input_external_id

            # Check if role arn is valid
            try:
                # this returns the arn already parsed, calls arnparse, into a dict to be used when it is needed to access its fields
                role_arn_parsed = arn_parsing(
                    current_audit_info.assumed_role_info.role_arn
                )

            except Exception as error:
                logger.critical(f"{error.__class__.__name__} -- {error}")
                sys.exit()

            else:
                logger.info(
                    f"Assuming role {current_audit_info.assumed_role_info.role_arn}"
                )
                # Assume the role
                assumed_role_response = assume_role(current_audit_info)
                logger.info("Role assumed")
                # Set the info needed to create a session with an assumed role
                current_audit_info.credentials = AWS_Credentials(
                    aws_access_key_id=assumed_role_response["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_session_token=assumed_role_response["Credentials"][
                        "SessionToken"
                    ],
                    aws_secret_access_key=assumed_role_response["Credentials"][
                        "SecretAccessKey"
                    ],
                    expiration=assumed_role_response["Credentials"]["Expiration"],
                )
                assumed_session = AWS_Provider(current_audit_info).get_session()

        if assumed_session:
            logger.info("Audit session is the new session created assuming role")
            current_audit_info.audit_session = assumed_session
            current_audit_info.audited_account = role_arn_parsed.account_id
            current_audit_info.audited_partition = role_arn_parsed.partition
        else:
            logger.info("Audit session is the original one")
            current_audit_info.audit_session = current_audit_info.original_session

        # Setting default region of session
        if current_audit_info.audit_session.region_name:
            current_audit_info.profile_region = (
                current_audit_info.audit_session.region_name
            )
        else:
            current_audit_info.profile_region = "us-east-1"

        self.print_audit_credentials(current_audit_info)
        return current_audit_info

    def set_azure_audit_info(self, arguments) -> Azure_Audit_Info:
        """
        set_azure_audit_info returns the Azure_Audit_Info
        """
        logger.info("Setting Azure session ...")
        subscription_ids = arguments.get("subscriptions")

        logger.info("Checking if any credentials mode is set ...")
        az_cli_auth = arguments.get("az_cli_auth")
        sp_env_auth = arguments.get("sp_env_auth")
        browser_auth = arguments.get("browser_auth")
        managed_entity_auth = arguments.get("managed_entity_auth")
        if (
            not az_cli_auth
            and not sp_env_auth
            and not browser_auth
            and not managed_entity_auth
        ):
            raise Exception(
                "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
            )

        azure_provider = Azure_Provider(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_entity_auth,
            subscription_ids,
        )
        azure_audit_info.credentials = azure_provider.get_credentials()
        azure_audit_info.identity = azure_provider.get_identity()

        return azure_audit_info


def set_provider_audit_info(provider: str, arguments: dict):
    """
    set_provider_audit_info configures automatically the audit session based on the selected provider and returns the audit_info object.
    """
    try:
        provider_set_audit_info = f"set_{provider}_audit_info"
        provider_audit_info = getattr(Audit_Info(), provider_set_audit_info)(arguments)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit()
    else:
        return provider_audit_info
