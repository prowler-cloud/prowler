from boto3 import session

from prowler.lib.logger import logger
from prowler.providers.aws.models import AWSOrganizationsInfo


def get_organizations_metadata(
    aws_account_id: str,
    session: session.Session,
) -> tuple[dict, dict]:
    try:
        organizations_client = session.client("organizations")

        organizations_metadata = organizations_client.describe_account(
            AccountId=aws_account_id
        )
        list_tags_for_resource = organizations_client.list_tags_for_resource(
            ResourceId=aws_account_id
        )

        return organizations_metadata, list_tags_for_resource
    except Exception as error:
        logger.warning(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return {}, {}


def parse_organizations_metadata(metadata: dict, tags: dict) -> AWSOrganizationsInfo:
    try:
        # Convert Tags dictionary to String
        account_details_tags = ""
        for tag in tags.get("Tags", {}):
            account_details_tags += tag["Key"] + ":" + tag["Value"] + ","

        account_details = metadata.get("Account", {})
        organizations_info = AWSOrganizationsInfo(
            account_details_email=account_details.get("Email", ""),
            account_details_name=account_details.get("Name", ""),
            account_details_arn=account_details.get("Arn", ""),
            account_details_org=account_details.get("Arn", "").split("/")[1],
            account_details_tags=account_details_tags.rstrip(","),
        )
        return organizations_info
    except Exception as error:
        logger.warning(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
