import json
from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


class SqsQueuesNotPubliclyAccessibleFixer(AWSFixer):
    """
    Fixer to remove public access from SQS queue policies and replace with trusted account access.
    """

    def __init__(self):
        super().__init__(
            description="Remove public access from SQS queue policies and replace with trusted account access.",
            cost_impact=False,
            cost_description=None,
            service="sqs",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sqs:SetQueueAttributes",
                        "Resource": "*",
                    }
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Remove public access from SQS queue policies and replace with trusted account access.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if the policy is updated, False otherwise.
        """
        try:
            if finding:
                region = finding.region
                resource_id = finding.resource_id
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("region and resource_id are required")

            super().fix(region=region, resource_id=resource_id)

            account_id = sqs_client.audited_account
            audited_partition = sqs_client.audited_partition
            regional_client = sqs_client.regional_clients[region]
            queue_name = resource_id.split("/")[-1]

            trusted_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ProwlerFixerStatement",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": account_id,
                        },
                        "Action": "sqs:*",
                        "Resource": f"arn:{audited_partition}:sqs:{region}:{account_id}:{queue_name}",
                    }
                ],
            }

            regional_client.set_queue_attributes(
                QueueUrl=resource_id,
                Attributes={"Policy": json.dumps(trusted_policy)},
            )
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
        else:
            return True
