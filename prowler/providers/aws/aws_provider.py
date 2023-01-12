import os
import pathlib
import sys

from boto3 import session
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

from prowler.config.config import aws_services_json_file
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file
from prowler.providers.aws.lib.audit_info.models import AWS_Assume_Role, AWS_Audit_Info


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


def assume_role(session: session.Session, assumed_role_info: AWS_Assume_Role) -> dict:
    try:
        # set the info to assume the role from the partition, account and role name
        sts_client = session.client("sts")
        # If external id, set it to the assume role api call
        if assumed_role_info.external_id:
            assumed_credentials = sts_client.assume_role(
                RoleArn=assumed_role_info.role_arn,
                RoleSessionName="ProwlerProAsessmentSession",
                DurationSeconds=assumed_role_info.session_duration,
                ExternalId=assumed_role_info.external_id,
            )
        # else assume the role without the external id
        else:
            assumed_credentials = sts_client.assume_role(
                RoleArn=assumed_role_info.role_arn,
                RoleSessionName="ProwlerProAsessmentSession",
                DurationSeconds=assumed_role_info.session_duration,
            )
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit()

    else:
        return assumed_credentials


def generate_regional_clients(
    service: str, audit_info: AWS_Audit_Info, global_service: bool = False
) -> dict:
    try:
        regional_clients = {}
        # Get json locally
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        f = open_file(f"{actual_directory}/{aws_services_json_file}")
        data = parse_json_file(f)
        # Check if it is a subservice
        json_regions = data["services"][service]["regions"][
            audit_info.audited_partition
        ]
        if audit_info.audited_regions:  # Check for input aws audit_info.audited_regions
            regions = list(
                set(json_regions).intersection(audit_info.audited_regions)
            )  # Get common regions between input and json
        else:  # Get all regions from json of the service and partition
            regions = json_regions
        # Check if it is global service to gather only one region
        if global_service:
            if regions:
                if audit_info.profile_region in regions:
                    regions = [audit_info.profile_region]
                regions = regions[:1]
        for region in regions:
            regional_client = audit_info.audit_session.client(
                service, region_name=region
            )
            regional_client.region = region
            regional_clients[region] = regional_client
        return regional_clients
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def get_aws_available_regions():
    try:
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        f = open_file(f"{actual_directory}/{aws_services_json_file}")
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
