import re

import yaml
from boto3 import Session
from boto3.dynamodb.conditions import Attr

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class AWSMutelist(Mutelist):
    def __init__(
        self,
        mutelist_content: dict = {},
        mutelist_path: str = None,
        session: Session = None,
        aws_account_id: str = "",
    ) -> "AWSMutelist":
        self._mutelist = mutelist_content
        self._mutelist_file_path = mutelist_path
        if mutelist_path:
            # Mutelist from S3 URI
            if re.search("^s3://([^/]+)/(.*?([^/]+))$", self._mutelist_file_path):
                self._mutelist = self.get_mutelist_file_from_s3(session)
            # Mutelist from Lambda Function ARN
            elif re.search(r"^arn:(\w+):lambda:", self._mutelist_file_path):
                self._mutelist = self.get_mutelist_file_from_lambda(
                    session,
                )
            # Mutelist from DynamoDB ARN
            elif re.search(
                r"^arn:aws(-cn|-us-gov)?:dynamodb:[a-z]{2}-[a-z-]+-[1-9]{1}:[0-9]{12}:table\/[a-zA-Z0-9._-]+$",
                self._mutelist_file_path,
            ):
                self._mutelist = self.get_mutelist_file_from_dynamodb(
                    session,
                    aws_account_id,
                )
            else:
                self.get_mutelist_file_from_local_file(mutelist_path)
        if self._mutelist:
            self.validate_mutelist()

    def is_finding_muted(
        self,
        finding: Check_Report_AWS,
        aws_account_id: str,
    ) -> bool:
        return self.is_muted(
            aws_account_id,
            finding.check_metadata.CheckID,
            finding.region,
            finding.resource_id,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )

    def get_mutelist_file_from_s3(self, aws_session: Session = None):
        try:
            bucket = self._mutelist_file_path.split("/")[2]
            key = ("/").join(self._mutelist_file_path.split("/")[3:])
            s3_client = aws_session.client("s3")
            mutelist = yaml.safe_load(
                s3_client.get_object(Bucket=bucket, Key=key)["Body"]
            )["Mutelist"]
            return mutelist
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
            )
            return {}

    def get_mutelist_file_from_lambda(self, aws_session: Session = None):
        try:
            lambda_region = self._mutelist_file_path.split(":")[3]
            lambda_client = aws_session.client("lambda", region_name=lambda_region)
            lambda_response = lambda_client.invoke(
                FunctionName=self._mutelist_file_path, InvocationType="RequestResponse"
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
        self, aws_session: Session = None, aws_account: str = None
    ):
        try:
            mutelist = {"Accounts": {}}
            table_region = self._mutelist_file_path.split(":")[3]
            dynamodb_resource = aws_session.resource(
                "dynamodb", region_name=table_region
            )
            dynamo_table = dynamodb_resource.Table(
                self._mutelist_file_path.split("/")[1]
            )
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
