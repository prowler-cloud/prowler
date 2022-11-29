import sys

from arnparse import arnparse
from boto3 import client, session
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
from colorama import Fore, Style

from config.config import aws_services_json_file
from lib.logger import logger
from lib.utils.utils import open_file, parse_json_file
from providers.aws.lib.arn.arn import arn_parsing
from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.lib.audit_info.models import (
    AWS_Audit_Info,
    AWS_Credentials,
    AWS_Organizations_Info,
)


################## AWS PROVIDER
class AWS_Provider:
    def __init__(self, audit_info):
        logger.info("Instantiating aws provider ...")
        self.aws_session = self.set_session(audit_info)
        self.role_info = audit_info.assumed_role_info

    def get_session(self):
        return self.aws_session

    def set_session(self, audit_info):
        try:
            if audit_info.credentials:
                # If we receive a credentials object filled is coming form an assumed role, so renewal is needed
                logger.info("Creating session for assumed role ...")
                # From botocore we can use RefreshableCredentials class, which has an attribute (refresh_using)
                # that needs to be a method without arguments that retrieves a new set of fresh credentials
                # asuming the role again. -> https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L395
                assumed_refreshable_credentials = RefreshableCredentials(
                    access_key=audit_info.credentials.aws_access_key_id,
                    secret_key=audit_info.credentials.aws_secret_access_key,
                    token=audit_info.credentials.aws_session_token,
                    expiry_time=audit_info.credentials.expiration,
                    refresh_using=self.refresh,
                    method="sts-assume-role",
                )
                # Here we need the botocore session since it needs to use refreshable credentials
                assumed_botocore_session = get_session()
                assumed_botocore_session._credentials = assumed_refreshable_credentials
                assumed_botocore_session.set_config_variable(
                    "region", audit_info.profile_region
                )

                return session.Session(
                    profile_name=audit_info.profile,
                    botocore_session=assumed_botocore_session,
                )
            # If we do not receive credentials start the session using the profile
            else:
                logger.info("Creating session for not assumed identity ...")
                return session.Session(profile_name=audit_info.profile)
        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            sys.exit()

    # Refresh credentials method using assume role
    # This method is called "adding ()" to the name, so it cannot accept arguments
    # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L570
    def refresh(self):
        logger.info("Refreshing assumed credentials...")

        response = assume_role(self.role_info)
        refreshed_credentials = dict(
            # Keys of the dict has to be the same as those that are being searched in the parent class
            # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L609
            access_key=response["Credentials"]["AccessKeyId"],
            secret_key=response["Credentials"]["SecretAccessKey"],
            token=response["Credentials"]["SessionToken"],
            expiry_time=response["Credentials"]["Expiration"].isoformat(),
        )
        logger.info("Refreshed Credentials:")
        logger.info(refreshed_credentials)
        return refreshed_credentials


def aws_provider_set_session(
    input_profile,
    input_role,
    input_session_duration,
    input_external_id,
    input_regions,
    organizations_role_arn,
):
    # Assumed AWS session
    assumed_session = None

    # Setting session
    current_audit_info.profile = input_profile
    current_audit_info.audited_regions = input_regions

    logger.info("Generating original session ...")
    # Create an global original session using only profile/basic credentials info
    current_audit_info.original_session = AWS_Provider(current_audit_info).get_session()
    logger.info("Validating credentials ...")
    # Verificate if we have valid credentials
    caller_identity = validate_credentials(current_audit_info.original_session)

    logger.info("Credentials validated")
    logger.info(f"Original caller identity UserId : {caller_identity['UserId']}")
    logger.info(f"Original caller identity ARN : {caller_identity['Arn']}")

    current_audit_info.audited_account = caller_identity["Account"]
    current_audit_info.audited_identity_arn = caller_identity["Arn"]
    current_audit_info.audited_user_id = caller_identity["UserId"]
    current_audit_info.audited_partition = arnparse(caller_identity["Arn"]).partition

    logger.info("Checking if organizations role assumption is needed ...")
    if organizations_role_arn:
        current_audit_info.assumed_role_info.role_arn = organizations_role_arn
        current_audit_info.assumed_role_info.session_duration = input_session_duration

        # Check if role arn is valid
        try:
            # this returns the arn already parsed, calls arnparse, into a dict to be used when it is needed to access its fields
            role_arn_parsed = arn_parsing(current_audit_info.assumed_role_info.role_arn)

        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            sys.exit()

        else:
            logger.info(
                f"Getting organizations metadata for account {organizations_role_arn}"
            )
            assumed_credentials = assume_role(current_audit_info)
            current_audit_info.organizations_metadata = get_organizations_metadata(
                current_audit_info.audited_account, assumed_credentials
            )
            logger.info("Organizations metadata retrieved")

    logger.info("Checking if role assumption is needed ...")
    if input_role:
        current_audit_info.assumed_role_info.role_arn = input_role
        current_audit_info.assumed_role_info.session_duration = input_session_duration
        current_audit_info.assumed_role_info.external_id = input_external_id

        # Check if role arn is valid
        try:
            # this returns the arn already parsed, calls arnparse, into a dict to be used when it is needed to access its fields
            role_arn_parsed = arn_parsing(current_audit_info.assumed_role_info.role_arn)

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
                aws_access_key_id=assumed_role_response["Credentials"]["AccessKeyId"],
                aws_session_token=assumed_role_response["Credentials"]["SessionToken"],
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
        current_audit_info.profile_region = current_audit_info.audit_session.region_name
    else:
        current_audit_info.profile_region = "us-east-1"

    print_audit_credentials(current_audit_info)
    return current_audit_info


def print_audit_credentials(audit_info: AWS_Audit_Info):
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
        report += f"Assumed Role ARN: {Fore.YELLOW}[{audit_info.assumed_role_info.role_arn}]{Style.RESET_ALL}"
    print(report)


def validate_credentials(validate_session: session) -> dict:
    try:
        validate_credentials_client = validate_session.client("sts")
        caller_identity = validate_credentials_client.get_caller_identity()
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit()
    else:
        return caller_identity


def assume_role(audit_info: AWS_Audit_Info) -> dict:
    try:
        # set the info to assume the role from the partition, account and role name
        sts_client = audit_info.original_session.client("sts")
        # If external id, set it to the assume role api call
        if audit_info.assumed_role_info.external_id:
            assumed_credentials = sts_client.assume_role(
                RoleArn=audit_info.assumed_role_info.role_arn,
                RoleSessionName="ProwlerProAsessmentSession",
                DurationSeconds=audit_info.assumed_role_info.session_duration,
                ExternalId=audit_info.assumed_role_info.external_id,
            )
        # else assume the role without the external id
        else:
            assumed_credentials = sts_client.assume_role(
                RoleArn=audit_info.assumed_role_info.role_arn,
                RoleSessionName="ProwlerProAsessmentSession",
                DurationSeconds=audit_info.assumed_role_info.session_duration,
            )
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit()

    else:
        return assumed_credentials


def get_organizations_metadata(
    metadata_account: str, assumed_credentials: dict
) -> AWS_Organizations_Info:
    try:
        organizations_client = client(
            "organizations",
            aws_access_key_id=assumed_credentials["Credentials"]["AccessKeyId"],
            aws_secret_access_key=assumed_credentials["Credentials"]["SecretAccessKey"],
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
            account_details_org=organizations_metadata["Account"]["Arn"].split("/")[1],
            account_details_tags=account_details_tags,
        )
        return organizations_info


def generate_regional_clients(service: str, audit_info: AWS_Audit_Info) -> dict:
    regional_clients = {}
    # Get json locally
    f = open_file(aws_services_json_file)
    data = parse_json_file(f)
    # Check if it is a subservice
    if service == "accessanalyzer":
        json_regions = data["services"]["iam"]["regions"][audit_info.audited_partition]
    elif service == "apigatewayv2":
        json_regions = data["services"]["apigateway"]["regions"][
            audit_info.audited_partition
        ]
    elif service == "macie2":
        json_regions = data["services"]["macie"]["regions"][
            audit_info.audited_partition
        ]
    elif service == "logs":
        json_regions = data["services"]["cloudwatch"]["regions"][
            audit_info.audited_partition
        ]
    elif service == "dax":
        json_regions = data["services"]["dynamodb"]["regions"][
            audit_info.audited_partition
        ]
    elif service == "glacier":
        json_regions = data["services"]["s3"]["regions"][audit_info.audited_partition]
    elif service == "opensearch":
        json_regions = data["services"]["es"]["regions"][audit_info.audited_partition]
    elif service == "elbv2":
        json_regions = data["services"]["elb"]["regions"][audit_info.audited_partition]
    elif service == "wafv2" or service == "waf-regional":
        json_regions = data["services"]["waf"]["regions"][audit_info.audited_partition]
    else:
        json_regions = data["services"][service]["regions"][
            audit_info.audited_partition
        ]
    if audit_info.audited_regions:  # Check for input aws audit_info.audited_regions
        regions = list(
            set(json_regions).intersection(audit_info.audited_regions)
        )  # Get common regions between input and json
    else:  # Get all regions from json of the service and partition
        regions = json_regions
    for region in regions:
        regional_client = audit_info.audit_session.client(service, region_name=region)
        regional_client.region = region
        regional_clients[region] = regional_client
        # regional_clients.append(regional_client)
    return regional_clients


def get_region_global_service(audit_info: AWS_Audit_Info) -> str:
    # Check if global service to send the finding to first audited region
    if audit_info.audited_regions:
        return audit_info.audited_regions[0]
    return audit_info.profile_region
