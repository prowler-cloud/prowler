import sys

from boto3 import client

from prowler.lib.logger import logger
from prowler.providers.aws.lib.audit_info.models import AWSOrganizationsInfo


def get_organizations_metadata(
    metadata_account: str, assumed_credentials: dict
) -> AWSOrganizationsInfo:
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
        sys.exit(1)
    else:
        # Convert Tags dictionary to String
        account_details_tags = ""
        for tag in list_tags_for_resource["Tags"]:
            account_details_tags += tag["Key"] + ":" + tag["Value"] + ","
        organizations_info = AWSOrganizationsInfo(
            account_details_email=organizations_metadata["Account"]["Email"],
            account_details_name=organizations_metadata["Account"]["Name"],
            account_details_arn=organizations_metadata["Account"]["Arn"],
            account_details_org=organizations_metadata["Account"]["Arn"].split("/")[1],
            account_details_tags=account_details_tags,
        )
        return organizations_info
