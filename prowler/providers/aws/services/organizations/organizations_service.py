import json
from typing import Optional

from botocore.client import ClientError
from pydantic.v1 import BaseModel

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
                organization_enabled_service_principals = (
                    self._list_aws_service_access_for_organization()
                )
                organization_delegated_service_principals = {}
                for delegated_administrator in (
                    organization_delegated_administrator or []
                ):
                    organization_delegated_service_principals[
                        delegated_administrator.id
                    ] = self._list_delegated_services_for_account(
                        delegated_administrator.id
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
                        enabled_service_principals=organization_enabled_service_principals,
                        delegated_service_principals=organization_delegated_service_principals,
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
        policies = {}
        try:
            list_policies_paginator = self.client.get_paginator("list_policies")
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
            # Any ClientError leaves the administrators unknown, not empty. Setting the
            # sentinel only for AccessDeniedException let a throttle or a service error
            # return the empty list, which reads as an organization that has none.
            self.delegated_administrators = None
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            self.delegated_administrators = None
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return self.delegated_administrators

    def _list_aws_service_access_for_organization(self):
        logger.info("Organizations - List AWS Service Access For Organization...")

        # None means the trusted access configuration could not be read, which is
        # not the same as an organization with no service integrated at all. The
        # service principal is read by key so that a response no longer carrying it
        # raises into the sentinel instead of yielding a list of None.
        enabled_service_principals = []
        try:
            list_aws_service_access_paginator = self.client.get_paginator(
                "list_aws_service_access_for_organization"
            )
            for page in list_aws_service_access_paginator.paginate():
                for enabled_service_principal in page["EnabledServicePrincipals"]:
                    enabled_service_principals.append(
                        enabled_service_principal["ServicePrincipal"]
                    )

        except ClientError as error:
            enabled_service_principals = None
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            enabled_service_principals = None
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return enabled_service_principals

    def _list_delegated_services_for_account(self, account_id):
        logger.info(
            "Organizations - List Delegated Services For Account: %s ...", account_id
        )

        # None means the delegations of this account could not be read, which is not
        # the same as an account that administers no service. The service principal is
        # read by key so that a response no longer carrying it raises into the sentinel
        # instead of yielding a list of None.
        delegated_service_principals = []
        try:
            list_delegated_services_paginator = self.client.get_paginator(
                "list_delegated_services_for_account"
            )
            for page in list_delegated_services_paginator.paginate(
                AccountId=account_id
            ):
                for delegated_service in page["DelegatedServices"]:
                    delegated_service_principals.append(
                        delegated_service["ServicePrincipal"]
                    )

        except ClientError as error:
            delegated_service_principals = None
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            delegated_service_principals = None
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return delegated_service_principals


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
    enabled_service_principals: Optional[list[str]] = None
    delegated_service_principals: Optional[dict[str, Optional[list[str]]]] = None
