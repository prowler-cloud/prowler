from typing import Optional

from pydantic import BaseModel

from prowler.providers.aws.lib.arn.error import RoleArnParsingFailedMissingFields


class ARN(BaseModel):
    partition: str
    service: str
    region: Optional[str]  # In IAM ARN's do not have region
    account_id: str
    resource: str
    resource_type: str

    def __init__(self, arn):
        # Validate the ARN
        ## Check that arn starts with arn
        if not arn.startswith("arn:"):
            raise RoleArnParsingFailedMissingFields
        ## Retrieve fields
        arn_elements = arn.split(":", 5)
        data = {
            "partition": arn_elements[1],
            "service": arn_elements[2],
            "region": arn_elements[3] if arn_elements[3] != "" else None,
            "account_id": arn_elements[4],
            "resource": arn_elements[5],
            "resource_type": get_arn_resource_type(arn, arn_elements[2]),
        }
        if "/" in data["resource"]:
            data["resource"] = data["resource"].split("/", 1)[1]
        elif ":" in data["resource"]:
            data["resource"] = data["resource"].split(":", 1)[1]

        # Calls Pydantic's BaseModel __init__
        super().__init__(**data)


def get_arn_resource_type(arn, service):
    if service == "s3":
        resource_type = "bucket"
    elif service == "sns":
        resource_type = "topic"
    elif service == "sqs":
        resource_type = "queue"
    elif service == "apigateway":
        split_parts = arn.split(":")[5].split("/")
        if "integration" in split_parts and "responses" in split_parts:
            resource_type = "restapis-resources-methods-integration-response"
        elif "documentation" in split_parts and "parts" in split_parts:
            resource_type = "restapis-documentation-parts"
        else:
            resource_type = arn.split(":")[5].split("/")[1]
    else:
        resource_type = arn.split(":")[5].split("/")[0]
    return resource_type
