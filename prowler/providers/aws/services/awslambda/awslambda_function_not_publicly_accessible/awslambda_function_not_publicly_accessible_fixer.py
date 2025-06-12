import json
from typing import Optional

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.logger import logger
from prowler.providers.aws.lib.fix.fixer import AWSFixer
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class LambdaFunctionNotPubliclyAccessibleFixer(AWSFixer):
    """
    Fixer for removing public access from Lambda function policies.
    """

    def __init__(self):
        super().__init__(
            description="Remove public access from Lambda function's resource-based policy and add a new permission for the account.",
            cost_impact=False,
            cost_description=None,
            service="awslambda",
            iam_policy_required={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:RemovePermission",
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": "lambda:AddPermission",
                        "Resource": "*",
                    },
                ],
            },
        )

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        Remove the Lambda function's resource-based policy to prevent public access and add a new permission for the account.
        Args:
            finding (Optional[Check_Report_AWS]): Finding to fix
            **kwargs: region, resource_id (if finding is not provided)
        Returns:
            bool: True if the operation is successful, False otherwise.
        """
        try:
            if finding:
                region = finding.region
                resource_id = finding.resource_id
            else:
                region = kwargs.get("region")
                resource_id = kwargs.get("resource_id")

            if not region or not resource_id:
                raise ValueError("Region and resource_id are required")

            super().fix(region=region, resource_id=resource_id)

            account_id = awslambda_client.audited_account
            regional_client = awslambda_client.regional_clients[region]
            policy_response = regional_client.get_policy(FunctionName=resource_id)
            policy = json.loads(policy_response.get("Policy"))

            for statement in policy.get("Statement", []):
                statement_id = statement.get("Sid")
                if statement_id:
                    regional_client.remove_permission(
                        FunctionName=resource_id, StatementId=statement_id
                    )

            regional_client.add_permission(
                FunctionName=resource_id,
                StatementId="ProwlerFixerStatement",
                Principal=account_id,
                Action="lambda:InvokeFunction",
            )
            return True
        except Exception as error:
            logger.error(
                f"{region if 'region' in locals() else 'unknown'} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
