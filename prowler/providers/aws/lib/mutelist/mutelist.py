import yaml
from boto3 import Session
from boto3.dynamodb.conditions import Attr

from prowler.lib.logger import logger


def get_mutelist_file_from_s3(mutelist_path: str, aws_session: Session = None):
    try:
        bucket = mutelist_path.split("/")[2]
        key = ("/").join(mutelist_path.split("/")[3:])
        s3_client = aws_session.client("s3")
        mutelist = yaml.safe_load(s3_client.get_object(Bucket=bucket, Key=key)["Body"])[
            "Mutelist"
        ]
        return mutelist
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return {}


def get_mutelist_file_from_lambda(mutelist_path: str, aws_session: Session = None):
    try:
        lambda_region = mutelist_path.split(":")[3]
        lambda_client = aws_session.client("lambda", region_name=lambda_region)
        lambda_response = lambda_client.invoke(
            FunctionName=mutelist_path, InvocationType="RequestResponse"
        )
        lambda_payload = lambda_response["Payload"].read()
        mutelist = yaml.safe_load(lambda_payload)["Mutelist"]

        return mutelist
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return {}


def get_mutelist_file_from_dynamodb(
    mutelist_path: str, aws_session: Session = None, aws_account: str = None
):
    try:
        mutelist = {"Accounts": {}}
        table_region = mutelist_path.split(":")[3]
        dynamodb_resource = aws_session.resource("dynamodb", region_name=table_region)
        dynamo_table = dynamodb_resource.Table(mutelist_path.split("/")[1])
        response = dynamo_table.scan(
            FilterExpression=Attr("Accounts").is_in([aws_account, "*"])
        )
        dynamodb_items = response["Items"]
        # Paginate through all results
        while "LastEvaluatedKey" in dynamodb_items:
            response = dynamo_table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"],
                FilterExpression=Attr("Accounts").is_in([aws_account, "*"]),
            )
            dynamodb_items.update(response["Items"])
        for item in dynamodb_items:
            # Create mutelist for every item
            mutelist["Accounts"][item["Accounts"]] = {
                "Checks": {
                    item["Checks"]: {
                        "Regions": item["Regions"],
                        "Resources": item["Resources"],
                    }
                }
            }
            if "Tags" in item:
                mutelist["Accounts"][item["Accounts"]]["Checks"][item["Checks"]][
                    "Tags"
                ] = item["Tags"]
            if "Exceptions" in item:
                mutelist["Accounts"][item["Accounts"]]["Checks"][item["Checks"]][
                    "Exceptions"
                ] = item["Exceptions"]
            return mutelist
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return {}
