import json
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService

AVAILABLE_ORGANIZATIONS_POLICIES = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY",
    "AISERVICES_OPT_OUT_POLICY",
]


class Organizations(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.organization = None
        self.policies = {}
        self.delegated_administrators = []
        self._describe_organization()

    def _describe_organization(self):
        logger.info("Organizations - Describe Organization...")

        try:
            try:
                organization_desc = self.client.describe_organization()["Organization"]
                organization_arn = organization_desc.get("Arn")
                organization_id = organization_desc.get("Id")
                organization_master_id = organization_desc.get("MasterAccountId")
                organization_policies = self._list_policies()
                organization_delegated_administrator = (
                    self._list_delegated_administrators()
                )
            except ClientError as error:
                if (
                    error.response["Error"]["Code"]
                    == "AWSOrganizationsNotInUseException"
                ):
                    self.organization = Organization(
                        arn=self.get_unknown_arn(),
                        id="unknown",
                        status="NOT_AVAILABLE",
                        master_id="",
                    )
                else:
                    logger.error(
                        f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            else:
                if not self.audit_resources or (
                    is_resource_filtered(organization_arn, self.audit_resources)
                ):
                    self.organization = Organization(
                        arn=organization_arn,
                        id=organization_id,
                        status="ACTIVE",
                        master_id=organization_master_id,
                        policies=organization_policies,
                        delegated_administrators=organization_delegated_administrator,
                    )
                else:
                    self.organization = Organization(
                        arn=self.get_unknown_arn(),
                        id="unknown",
                        status="NOT_AVAILABLE",
                        master_id="",
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_policies(self):
        logger.info("Organizations - List policies...")

        try:
            list_policies_paginator = self.client.get_paginator("list_policies")
            policies = {}
            for policy_type in AVAILABLE_ORGANIZATIONS_POLICIES:
                logger.info(
                    "Organizations - List policies... - Type: %s",
                    policy_type,
                )
                policies[policy_type] = []
                for page in list_policies_paginator.paginate(Filter=policy_type):
                    for policy in page["Policies"]:
                        policy_id = policy.get("Id")
                        policy_content = self._describe_policy(policy_id)
                        policy_targets = self._list_targets_for_policy(policy_id)
                        policies[policy_type].append(
                            Policy(
                                arn=policy.get("Arn"),
                                id=policy_id,
                                type=policy.get("Type"),
                                aws_managed=policy.get("AwsManaged"),
                                content=policy_content,
                                targets=policy_targets,
                            )
                        )

        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                policies = None
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        finally:
            return policies

    def _describe_policy(self, policy_id) -> dict:
        logger.info("Organizations - Describe policy: %s ...", policy_id)
        try:
            policy_content = {}
            if policy_id:
                policy_content = (
                    self.client.describe_policy(PolicyId=policy_id)
                    .get("Policy", {})
                    .get("Content", "")
                )
                if isinstance(policy_content, str):
                    policy_content = json.loads(policy_content)

            return policy_content
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def _list_targets_for_policy(self, policy_id) -> list:
        logger.info("Organizations - List Targets for policy: %s ...", policy_id)

        try:
            targets_for_policy = []
            if policy_id:
                targets_for_policy = self.client.list_targets_for_policy(
                    PolicyId=policy_id
                )["Targets"]

            return targets_for_policy

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def _list_delegated_administrators(self):
        logger.info("Organizations - List Delegated Administrators...")

        try:
            list_delegated_administrators_paginator = self.client.get_paginator(
                "list_delegated_administrators"
            )
            for page in list_delegated_administrators_paginator.paginate():
                for delegated_administrator in page["DelegatedAdministrators"]:
                    self.delegated_administrators.append(
                        DelegatedAdministrator(
                            arn=delegated_administrator.get("Arn"),
                            id=delegated_administrator.get("Id"),
                            name=delegated_administrator.get("Name"),
                            email=delegated_administrator.get("Email"),
                            status=delegated_administrator.get("Status"),
                            joinedmethod=delegated_administrator.get("JoinedMethod"),
                        )
                    )

        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                self.delegated_administrators = None

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        finally:
            return self.delegated_administrators


class Policy(BaseModel):
    arn: str
    id: str
    type: str
    aws_managed: bool
    content: dict = {}
    targets: Optional[list] = []


class DelegatedAdministrator(BaseModel):
    arn: str
    id: str
    name: str
    email: str
    status: str
    joinedmethod: str


class Organization(BaseModel):
    arn: str
    id: str
    status: str
    master_id: str
    policies: Optional[dict[str, list[Policy]]] = {}
    delegated_administrators: list[DelegatedAdministrator] = None
