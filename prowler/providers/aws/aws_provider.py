import os
import pathlib
import sys

from boto3 import client, session
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

from prowler.config.config import aws_services_json_file
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file
from prowler.providers.aws.config import (
    AWS_STS_GLOBAL_ENDPOINT_REGION,
    ROLE_SESSION_NAME,
)
from prowler.providers.aws.lib.audit_info.models import AWSAssumeRole
from prowler.providers.aws.lib.credentials.credentials import create_sts_session


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
            # If we receive a credentials object filled is coming form an assumed role, so renewal is needed
            if audit_info.credentials:
                logger.info("Creating session for assumed role ...")
                # From botocore we can use RefreshableCredentials class, which has an attribute (refresh_using)
                # that needs to be a method without arguments that retrieves a new set of fresh credentials
                # asuming the role again. -> https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L395
                assumed_refreshable_credentials = RefreshableCredentials(
                    access_key=audit_info.credentials.aws_access_key_id,
                    secret_key=audit_info.credentials.aws_secret_access_key,
                    token=audit_info.credentials.aws_session_token,
                    expiry_time=audit_info.credentials.expiration,
                    refresh_using=self.refresh_credentials,
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
                # Input MFA only if a role is not going to be assumed
                if audit_info.mfa_enabled and not audit_info.assumed_role_info.role_arn:
                    mfa_ARN, mfa_TOTP = input_role_mfa_token_and_code()
                    get_session_token_arguments = {
                        "SerialNumber": mfa_ARN,
                        "TokenCode": mfa_TOTP,
                    }
                    sts_client = client("sts")
                    session_credentials = sts_client.get_session_token(
                        **get_session_token_arguments
                    )
                    return session.Session(
                        aws_access_key_id=session_credentials["Credentials"][
                            "AccessKeyId"
                        ],
                        aws_secret_access_key=session_credentials["Credentials"][
                            "SecretAccessKey"
                        ],
                        aws_session_token=session_credentials["Credentials"][
                            "SessionToken"
                        ],
                        profile_name=audit_info.profile,
                    )
                else:
                    return session.Session(
                        profile_name=audit_info.profile,
                    )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            sys.exit(1)

    # Refresh credentials method using assume role
    # This method is called "adding ()" to the name, so it cannot accept arguments
    # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L570
    def refresh_credentials(self):
        logger.info("Refreshing assumed credentials...")

        response = assume_role(self.aws_session, self.role_info)
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


def assume_role(
    session: session.Session,
    assumed_role_info: AWSAssumeRole,
    sts_endpoint_region: str = None,
) -> dict:
    try:
        role_session_name = (
            assumed_role_info.role_session_name
            if assumed_role_info.role_session_name
            else ROLE_SESSION_NAME
        )

        assume_role_arguments = {
            "RoleArn": assumed_role_info.role_arn,
            "RoleSessionName": role_session_name,
            "DurationSeconds": assumed_role_info.session_duration,
        }

        # Set the info to assume the role from the partition, account and role name
        if assumed_role_info.external_id:
            assume_role_arguments["ExternalId"] = assumed_role_info.external_id

        if assumed_role_info.mfa_enabled:
            mfa_ARN, mfa_TOTP = input_role_mfa_token_and_code()
            assume_role_arguments["SerialNumber"] = mfa_ARN
            assume_role_arguments["TokenCode"] = mfa_TOTP

        # Set the STS Endpoint Region
        if sts_endpoint_region is None:
            sts_endpoint_region = AWS_STS_GLOBAL_ENDPOINT_REGION

        sts_client = create_sts_session(session, sts_endpoint_region)
        assumed_credentials = sts_client.assume_role(**assume_role_arguments)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)

    else:
        return assumed_credentials


def input_role_mfa_token_and_code() -> tuple[str]:
    """input_role_mfa_token_and_code ask for the AWS MFA ARN and TOTP and returns it."""
    mfa_ARN = input("Enter ARN of MFA: ")
    mfa_TOTP = input("Enter MFA code: ")
    return (mfa_ARN.strip(), mfa_TOTP.strip())


def get_aws_available_regions():
    try:
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open_file(f"{actual_directory}/{aws_services_json_file}") as f:
            data = parse_json_file(f)

        regions = set()
        for service in data["services"].values():
            for partition in service["regions"]:
                for item in service["regions"][partition]:
                    regions.add(item)
        return list(regions)
    except Exception as error:
        logger.error(f"{error.__class__.__name__}: {error}")
        return []
