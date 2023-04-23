from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## FMS
class FMS:
    def __init__(self, audit_info):
        self.service = "fms"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audited_partition = audit_info.audited_partition
        self.audit_resources = audit_info.audit_resources
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        self.client = list(global_client.values())[0]
        self.region = self.client.region
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
                            is_resource_filtered(fms_policy["PolicyArn"], self.audit_resources)
                        ):
                            self.fms_policies.append(
                                FMSPolicy(
                                    arn=fms_policy["PolicyArn"],
                                    id=fms_policy["PolicyId"],
                                    name=fms_policy["PolicyName"],
                                    resource_type=fms_policy["ResourceType"],
                                    service_type=fms_policy["SecurityServiceType"],
                                    remediation_enabled=fms_policy["RemediationEnabled"],
                                    delete_unused_managed_resources=fms_policy[
                                        "DeleteUnusedFMManagedResources"
                                    ],
                                )
                            )
            except ClientError as error:
                if error.response["Error"]["Code"] == "AccessDeniedException":
                    print(error.response)
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
                    for fms_compliance_status in page["PolicyComplianceStatusList"]:
                        fms_policy.compliance_status.append(
                            FMSPolicyAccountComplianceStatus(
                                account_id=fms_compliance_status["MemberAccount"],
                                policy_id=fms_compliance_status["PolicyId"],
                                status=fms_compliance_status["EvaluationResults"][0][
                                    "ComplianceStatus"
                                ],
                            )
                        )
                    fms_policy.compliance_status.append = fms_compliance_status

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class FMSPolicyAccountComplianceStatus(BaseModel):
    account_id: str
    policy_id: str
    status: str


class FMSPolicy(BaseModel):
    arn: str
    id: str
    name: str
    resource_type: str
    service_type: str
    remediation_enabled: bool
    delete_unused_managed_resources: bool
    compliance_status: list[FMSPolicyAccountComplianceStatus] = []
