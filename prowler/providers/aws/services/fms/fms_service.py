from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## FMS
class FMS(AWSService):
    def __init__(self, audit_info):
        # # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info, global_service=True)
        self.policy_arn_template = f"arn:{self.audited_partition}:fms:{self.region}:{self.audited_account}:policy"
        self.fms_admin_account = True
        self.fms_policies = []
        self.__list_policies__()
        self.__list_compliance_status__()

    def __list_policies__(self):
        logger.info("FMS - Listing Policies...")
        try:
            list_policies_paginator = self.client.get_paginator("list_policies")
            try:
                for page in list_policies_paginator.paginate():
                    for fms_policy in page["PolicyList"]:
                        if not self.audit_resources or (
                            is_resource_filtered(
                                fms_policy["PolicyArn"], self.audit_resources
                            )
                        ):
                            self.fms_policies.append(
                                Policy(
                                    arn=fms_policy.get("PolicyArn"),
                                    id=fms_policy.get("PolicyId"),
                                    name=fms_policy.get("PolicyName"),
                                    resource_type=fms_policy.get("ResourceType"),
                                    service_type=fms_policy.get("SecurityServiceType"),
                                    remediation_enabled=fms_policy.get(
                                        "RemediationEnabled"
                                    ),
                                    delete_unused_managed_resources=fms_policy.get(
                                        "DeleteUnusedFMManagedResources"
                                    ),
                                )
                            )
            except ClientError as error:
                if error.response["Error"]["Code"] == "AccessDeniedException":
                    if (
                        "No default admin could be found for account"
                        in error.response["Error"]["Message"]
                    ):
                        # FMS is not enabled in this account
                        self.fms_admin_account = False
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __list_compliance_status__(self):
        logger.info("FMS - Listing Policies...")
        try:
            for fms_policy in self.fms_policies:
                list_compliance_status_paginator = self.client.get_paginator(
                    "list_compliance_status"
                )
                for page in list_compliance_status_paginator.paginate(
                    PolicyId=fms_policy.id
                ):
                    for fms_compliance_status in page.get(
                        "PolicyComplianceStatusList", []
                    ):
                        compliance_status = ""
                        if fms_compliance_status.get("EvaluationResults"):
                            compliance_status = fms_compliance_status.get(
                                "EvaluationResults"
                            )[0].get("ComplianceStatus", "")
                        fms_policy.compliance_status.append(
                            PolicyAccountComplianceStatus(
                                account_id=fms_compliance_status.get("MemberAccount"),
                                policy_id=fms_compliance_status.get("PolicyId"),
                                status=compliance_status,
                            )
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class PolicyAccountComplianceStatus(BaseModel):
    account_id: str
    policy_id: str
    status: str


class Policy(BaseModel):
    arn: str
    id: str
    name: str
    resource_type: str
    service_type: str
    remediation_enabled: bool
    delete_unused_managed_resources: bool
    compliance_status: list[PolicyAccountComplianceStatus] = []
