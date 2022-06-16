from dataclasses import dataclass
from datetime import datetime

from arnparse import arnparse
from boto3 import session
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

from lib.logger import logger


@dataclass
class AWS_Credentials:
    aws_access_key_id: str
    aws_session_token: str
    aws_secret_access_key: str
    expiration: datetime


@dataclass
class Input_Data:
    profile: str
    role_name: str
    account_to_assume: str
    session_duration: int
    external_id: str


@dataclass
class AWS_Assume_Role:
    role_name: str
    account_to_assume: str
    session_duration: int
    external_id: str
    sts_session: session
    caller_identity: str


@dataclass
class AWS_Session_Info:
    profile: str
    credentials: AWS_Credentials
    role_info: AWS_Assume_Role


# ################## AWS PROVIDER
# # class AWS_Provider:
#      def __init__(self, profile, aws_regions):
        # self.aws_session = session.Session(profile_name=profile)
        # self.regions = aws_regions
        # self.account = self.aws_session.client('sts').get_caller_identity()["Account"]
        # self.caller = self.aws_session.client('sts').get_caller_identity()["Arn"]
        # self.partition = self.aws_session.client('sts').get_caller_identity()["Arn"].split(":")[1]

#     def get_session(self):
#         return self.aws_session

#     def get_regions(self):
#         return self.regions

#     def get_account(self):
#         return self.account
    
#     def get_caller(self):
#         return self.caller
    
#     def get_partition(self):
#         return self.partition

# def set_provider(profile,aws_regions):
#     global session
#     global regions
#     global account
#     global partition
#     provider = AWS_Provider(profile,aws_regions)
#     regions = provider.get_regions()
#     session = provider.get_session()
#     account = provider.get_account()
#     partition = provider.get_partition()

################## AWS PROVIDER
class AWS_Provider:
    def __init__(self, session_info):
        self.aws_session = self.set_session(session_info)
        self.role_info = session_info.role_info

    def get_session(self):
        return self.aws_session

    def set_session(self, session_info):
        try:
            if session_info.credentials:
                # If we receive a credentials object filled is coming form an assumed role, so renewal is needed
                logger.info("Creating session for assumed role ...")
                # From botocore we can use RefreshableCredentials class, which has an attribute (refresh_using)
                # that needs to be a method without arguments that retrieves a new set of fresh credentials
                # asuming the role again. -> https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L395
                assumed_refreshable_credentials = RefreshableCredentials(
                    access_key=session_info.credentials.aws_access_key_id,
                    secret_key=session_info.credentials.aws_secret_access_key,
                    token=session_info.credentials.aws_session_token,
                    expiry_time=session_info.credentials.expiration,
                    refresh_using=self.refresh,
                    method="sts-assume-role",
                )
                # Here we need the botocore session since it needs to use refreshable credentials
                assumed_botocore_session = get_session()
                assumed_botocore_session._credentials = assumed_refreshable_credentials
                assumed_botocore_session.set_config_variable("region", "us-east-1")

                return session.Session(
                    profile_name=session_info.profile,
                    botocore_session=assumed_botocore_session,
                )
            # If we do not receive credentials start the session using the profile
            else:
                logger.info("Creating session for not assumed identity ...")
                return session.Session(profile_name=session_info.profile)
        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            quit()

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


def validate_credentials(validate_session):

    try:
        validate_credentials_client = validate_session.client("sts")
        caller_identity = validate_credentials_client.get_caller_identity()
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        quit()
    else:
        return caller_identity


def provider_set_session(session_input):
    global aws_session
    global original_session
    session_info = AWS_Session_Info(
        session_input.profile,
        None,
        None,
    )

    original_session = AWS_Provider(session_info).get_session()
    logger.info("Validating credentials ...")
    caller_identity = validate_credentials(original_session)

    role_info = AWS_Assume_Role(
        session_input.role_name,
        session_input.account_to_assume,
        session_input.session_duration,
        session_input.external_id,
        original_session,
        caller_identity,
    )
    logger.info("Credentials validated")
    logger.info(f"Original caller identity UserId : {caller_identity['UserId']}")
    logger.info(f"Original caller identity ARN : {caller_identity['Arn']}")

    if session_input.role_name and session_input.account_to_assume:
        logger.info(
            f"Assuming role {role_info.role_name} in account {role_info.account_to_assume}"
        )
        assumed_role_response = assume_role(role_info)
        logger.info("Role assumed")
        session_info = AWS_Session_Info(
            session_input.profile,
            AWS_Credentials(
                aws_access_key_id=assumed_role_response["Credentials"]["AccessKeyId"],
                aws_session_token=assumed_role_response["Credentials"]["SessionToken"],
                aws_secret_access_key=assumed_role_response["Credentials"][
                    "SecretAccessKey"
                ],
                expiration=assumed_role_response["Credentials"]["Expiration"],
            ),
            role_info,
        )

    aws_session = AWS_Provider(session_info).get_session()


def assume_role(role_info):

    try:
        sts_client = role_info.sts_session.client("sts")
        arn_caller_identity = arnparse(role_info.caller_identity["Arn"])
        role_arn = f"arn:{arn_caller_identity.partition}:iam::{role_info.account_to_assume}:role/{role_info.role_name}"
        if role_info.external_id:
            assumed_credentials = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="ProwlerProSession",
                DurationSeconds=role_info.session_duration,
                ExternalId=role_info.external_id,
            )
        else:
            assumed_credentials = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="ProwlerProSession",
                DurationSeconds=role_info.session_duration,
            )
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        quit()

    else:
        return assumed_credentials
