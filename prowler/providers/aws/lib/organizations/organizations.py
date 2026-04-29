from boto3 import session

from prowler.lib.logger import logger
from prowler.providers.aws.lib.arn.models import ARN
from prowler.providers.aws.models import AWSOrganizationsInfo


def _get_ou_metadata(organizations_client, account_id):
    try:
        parents = organizations_client.list_parents(ChildId=account_id)["Parents"]
        if not parents:
            return {"ou_id": "", "ou_path": ""}

        parent = parents[0]
        if parent["Type"] == "ROOT":
            return {"ou_id": "", "ou_path": ""}

        direct_ou_id = parent["Id"]
        path_parts = []
        current_id = direct_ou_id

        while True:
            ou_info = organizations_client.describe_organizational_unit(
                OrganizationalUnitId=current_id
            )
            path_parts.append(ou_info["OrganizationalUnit"]["Name"])

            parents = organizations_client.list_parents(ChildId=current_id)["Parents"]
            if not parents or parents[0]["Type"] == "ROOT":
                break
            current_id = parents[0]["Id"]

        path_parts.reverse()
        return {"ou_id": direct_ou_id, "ou_path": "/".join(path_parts)}
    except Exception as error:
        logger.warning(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return {}


def get_organizations_metadata(
    aws_account_id: str,
    session: session.Session,
) -> tuple[dict, dict, dict]:
    try:
        organizations_client = session.client("organizations")

        organizations_metadata = organizations_client.describe_account(
            AccountId=aws_account_id
        )
        list_tags_for_resource = organizations_client.list_tags_for_resource(
            ResourceId=aws_account_id
        )

        ou_metadata = _get_ou_metadata(organizations_client, aws_account_id)

        return organizations_metadata, list_tags_for_resource, ou_metadata
    except Exception as error:
        logger.warning(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return {}, {}, {}


def parse_organizations_metadata(
    metadata: dict, tags: dict, ou_metadata: dict = None
) -> AWSOrganizationsInfo:
    try:
        # Convert Tags dictionary to String
        account_details_tags = {}
        for tag in tags.get("Tags", {}):
            account_details_tags[tag["Key"]] = tag["Value"]

        account_details = metadata.get("Account", {})

        aws_account_arn = ARN(account_details.get("Arn", ""))
        aws_organization_id = aws_account_arn.resource.split("/")[0]
        aws_organization_arn = f"arn:{aws_account_arn.partition}:organizations::{aws_account_arn.account_id}:organization/{aws_organization_id}"

        return AWSOrganizationsInfo(
            account_email=account_details.get("Email", ""),
            account_name=account_details.get("Name", ""),
            organization_account_arn=aws_account_arn.arn,
            organization_arn=aws_organization_arn,
            organization_id=aws_organization_id,
            account_tags=account_details_tags,
            account_ou_id=ou_metadata.get("ou_id", "") if ou_metadata else "",
            account_ou_name=ou_metadata.get("ou_path", "") if ou_metadata else "",
        )
    except Exception as error:
        logger.warning(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
