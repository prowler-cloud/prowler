import csv
from datetime import datetime
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


def is_service_role(role):
    try:
        if "Statement" in role["AssumeRolePolicyDocument"]:
            if isinstance(role["AssumeRolePolicyDocument"]["Statement"], list):
                for statement in role["AssumeRolePolicyDocument"]["Statement"]:
                    if (
                        statement["Effect"] == "Allow"
                        and (
                            "sts:AssumeRole" in statement["Action"]
                            or "sts:*" in statement["Action"]
                            or "*" in statement["Action"]
                        )
                        # This is what defines a service role
                        and "Service" in statement["Principal"]
                    ):
                        return True
            else:
                statement = role["AssumeRolePolicyDocument"]["Statement"]
                if (
                    statement["Effect"] == "Allow"
                    and (
                        "sts:AssumeRole" in statement["Action"]
                        or "sts:*" in statement["Action"]
                        or "*" in statement["Action"]
                    )
                    # This is what defines a service role
                    and "Service" in statement["Principal"]
                ):
                    return True
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    return False


################## IAM
class IAM(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.users = self.__get_users__()
        self.roles = self.__get_roles__()
        self.account_summary = self.__get_account_summary__()
        self.virtual_mfa_devices = self.__list_virtual_mfa_devices__()
        self.credential_report = self.__get_credential_report__()
        self.groups = self.__get_groups__()
        self.__get_group_users__()
        self.__list_attached_group_policies__()
        self.__list_attached_user_policies__()
        self.__list_attached_role_policies__()
        self.__list_inline_user_policies__()
        self.__list_mfa_devices__()
        self.password_policy = self.__get_password_policy__()
        support_policy_arn = (
            "arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"
        )
        self.entities_role_attached_to_support_policy = (
            self.__list_entities_role_for_policy__(support_policy_arn)
        )
        securityaudit_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
        self.entities_role_attached_to_securityaudit_policy = (
            self.__list_entities_role_for_policy__(securityaudit_policy_arn)
        )
        # List both Customer (attached and unattached) and AWS Managed (only attached) policies
        self.policies = []
        self.policies.extend(self.__list_policies__("AWS"))
        self.policies.extend(self.__list_policies__("Local"))
        self.__list_policies_version__(self.policies)
        self.saml_providers = self.__list_saml_providers__()
        self.server_certificates = self.__list_server_certificates__()
        self.__list_tags_for_resource__()

    def __get_client__(self):
        return self.client

    def __get_roles__(self):
        logger.info("IAM - List Roles...")
        try:
            roles = []
            get_roles_paginator = self.client.get_paginator("list_roles")
            for page in get_roles_paginator.paginate():
                for role in page["Roles"]:
                    if not self.audit_resources or (
                        is_resource_filtered(role["Arn"], self.audit_resources)
                    ):
                        roles.append(
                            Role(
                                name=role["RoleName"],
                                arn=role["Arn"],
                                assume_role_policy=role["AssumeRolePolicyDocument"],
                                is_service_role=is_service_role(role),
                            )
                        )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return roles

    def __get_credential_report__(self):
        logger.info("IAM - Get Credential Report...")
        report_is_completed = False
        credential_list = []
        try:
            while not report_is_completed:
                report_status = self.client.generate_credential_report()
                if report_status["State"] == "COMPLETE":
                    report_is_completed = True
            # Convert credential report to list of dictionaries
            credential = self.client.get_credential_report()["Content"].decode("utf-8")
            credential_lines = credential.split("\n")
            csv_reader = csv.DictReader(credential_lines, delimiter=",")
            credential_list = list(csv_reader)

        except ClientError as error:
            if error.response["Error"]["Code"] == "LimitExceededException":
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return credential_list

    def __get_groups__(self):
        logger.info("IAM - Get Groups...")
        try:
            groups = []
            get_groups_paginator = self.client.get_paginator("list_groups")
            for page in get_groups_paginator.paginate():
                for group in page["Groups"]:
                    if not self.audit_resources or (
                        is_resource_filtered(group["Arn"], self.audit_resources)
                    ):
                        groups.append(Group(name=group["GroupName"], arn=group["Arn"]))

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return groups

    def __get_account_summary__(self):
        logger.info("IAM - Get Account Summary...")
        try:
            account_summary = self.client.get_account_summary()
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            account_summary = None
        finally:
            return account_summary

    def __get_password_policy__(self):
        logger.info("IAM - Get Password Policy...")
        try:
            stored_password_policy = None
            password_policy = self.client.get_account_password_policy()[
                "PasswordPolicy"
            ]
            # Check if optional keys exist or not
            max_age = None
            reuse_prevention = None
            hard_expiry = None
            if "MaxPasswordAge" in password_policy:
                max_age = password_policy["MaxPasswordAge"]
            if "PasswordReusePrevention" in password_policy:
                reuse_prevention = password_policy["PasswordReusePrevention"]
            if "HardExpiry" in password_policy:
                hard_expiry = password_policy["HardExpiry"]

            stored_password_policy = PasswordPolicy(
                length=password_policy["MinimumPasswordLength"],
                symbols=password_policy["RequireSymbols"],
                numbers=password_policy["RequireNumbers"],
                uppercase=password_policy["RequireUppercaseCharacters"],
                lowercase=password_policy["RequireLowercaseCharacters"],
                allow_change=password_policy["AllowUsersToChangePassword"],
                expiration=password_policy["ExpirePasswords"],
                max_age=max_age,
                reuse_prevention=reuse_prevention,
                hard_expiry=hard_expiry,
            )
        except Exception as error:
            if "NoSuchEntity" in str(error):
                # Password policy does not exist
                stored_password_policy = None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        finally:
            return stored_password_policy

    def __get_users__(self):
        logger.info("IAM - List Users...")
        try:
            get_users_paginator = self.client.get_paginator("list_users")
            users = []
            for page in get_users_paginator.paginate():
                for user in page["Users"]:
                    if not self.audit_resources or (
                        is_resource_filtered(user["Arn"], self.audit_resources)
                    ):
                        if "PasswordLastUsed" not in user:
                            users.append(User(name=user["UserName"], arn=user["Arn"]))
                        else:
                            users.append(
                                User(
                                    name=user["UserName"],
                                    arn=user["Arn"],
                                    password_last_used=user["PasswordLastUsed"],
                                )
                            )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return users

    def __list_virtual_mfa_devices__(self):
        logger.info("IAM - List Virtual MFA Devices...")
        try:
            mfa_devices = []
            list_virtual_mfa_devices_paginator = self.client.get_paginator(
                "list_virtual_mfa_devices"
            )

            for page in list_virtual_mfa_devices_paginator.paginate():
                for mfa_device in page["VirtualMFADevices"]:
                    mfa_devices.append(mfa_device)
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return mfa_devices

    def __list_attached_group_policies__(self):
        logger.info("IAM - List Attached Group Policies...")
        try:
            for group in self.groups:
                list_attached_group_policies_paginator = self.client.get_paginator(
                    "list_attached_group_policies"
                )
                attached_group_policies = []
                for page in list_attached_group_policies_paginator.paginate(
                    GroupName=group.name
                ):
                    for attached_group_policy in page["AttachedPolicies"]:
                        attached_group_policies.append(attached_group_policy)

                group.attached_policies = attached_group_policies
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_group_users__(self):
        logger.info("IAM - Get Group Users...")
        try:
            for group in self.groups:
                get_group_paginator = self.client.get_paginator("get_group")
                group_users = []
                for page in get_group_paginator.paginate(GroupName=group.name):
                    for user in page["Users"]:
                        if "PasswordLastUsed" not in user:
                            group_users.append(
                                User(name=user["UserName"], arn=user["Arn"])
                            )
                        else:
                            group_users.append(
                                User(
                                    name=user["UserName"],
                                    arn=user["Arn"],
                                    password_last_used=user["PasswordLastUsed"],
                                )
                            )
                group.users = group_users
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_mfa_devices__(self):
        logger.info("IAM - List MFA Devices...")
        try:
            for user in self.users:
                list_mfa_devices_paginator = self.client.get_paginator(
                    "list_mfa_devices"
                )
                mfa_devices = []
                for page in list_mfa_devices_paginator.paginate(UserName=user.name):
                    for mfa_device in page["MFADevices"]:
                        mfa_serial_number = mfa_device["SerialNumber"]
                        mfa_type = (
                            mfa_device["SerialNumber"].split(":")[5].split("/")[0]
                        )
                        mfa_devices.append(
                            MFADevice(serial_number=mfa_serial_number, type=mfa_type)
                        )
                user.mfa_devices = mfa_devices
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_attached_user_policies__(self):
        logger.info("IAM - List Attached User Policies...")
        try:
            for user in self.users:
                attached_user_policies = []
                get_user_attached_policies_paginator = self.client.get_paginator(
                    "list_attached_user_policies"
                )
                for page in get_user_attached_policies_paginator.paginate(
                    UserName=user.name
                ):
                    for policy in page["AttachedPolicies"]:
                        attached_user_policies.append(policy)

                user.attached_policies = attached_user_policies

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_attached_role_policies__(self):
        logger.info("IAM - List Attached User Policies...")
        try:
            for role in self.roles:
                try:
                    attached_role_policies = []
                    list_attached_role_policies_paginator = self.client.get_paginator(
                        "list_attached_role_policies"
                    )
                    for page in list_attached_role_policies_paginator.paginate(
                        RoleName=role.name
                    ):
                        for policy in page["AttachedPolicies"]:
                            attached_role_policies.append(policy)

                    role.attached_policies = attached_role_policies
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntityException":
                        logger.warning(
                            f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_inline_user_policies__(self):
        logger.info("IAM - List Inline User Policies...")
        try:
            for user in self.users:
                inline_user_policies = []
                get_user_inline_policies_paginator = self.client.get_paginator(
                    "list_user_policies"
                )
                for page in get_user_inline_policies_paginator.paginate(
                    UserName=user.name
                ):
                    for policy in page["PolicyNames"]:
                        inline_user_policies.append(policy)

                user.inline_policies = inline_user_policies

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_entities_role_for_policy__(self, policy_arn):
        logger.info("IAM - List Entities Role For Policy...")
        try:
            roles = []
            roles = self.client.list_entities_for_policy(
                PolicyArn=policy_arn, EntityFilter="Role"
            )["PolicyRoles"]
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return roles

    def __list_policies__(self, scope):
        logger.info("IAM - List Policies...")
        try:
            policies = []
            list_policies_paginator = self.client.get_paginator("list_policies")
            for page in list_policies_paginator.paginate(
                Scope=scope, OnlyAttached=False if scope == "Local" else True
            ):  # Look for only Attached policies when AWS Managed
                for policy in page["Policies"]:
                    if not self.audit_resources or (
                        is_resource_filtered(policy["Arn"], self.audit_resources)
                    ):
                        policies.append(
                            Policy(
                                name=policy["PolicyName"],
                                arn=policy["Arn"],
                                version_id=policy["DefaultVersionId"],
                                type="Custom" if scope == "Local" else "AWS",
                                attached=True
                                if policy["AttachmentCount"] > 0
                                else False,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return policies

    def __list_policies_version__(self, policies):
        logger.info("IAM - List Policies Version...")
        try:
            for policy in policies:
                try:
                    policy_version = self.client.get_policy_version(
                        PolicyArn=policy.arn, VersionId=policy.version_id
                    )
                    policy.document = policy_version["PolicyVersion"]["Document"]
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntity":
                        logger.warning(
                            f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    continue
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_saml_providers__(self):
        logger.info("IAM - List SAML Providers...")
        try:
            saml_providers = self.client.list_saml_providers()["SAMLProviderList"]
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            saml_providers = None
        finally:
            return saml_providers

    def __list_server_certificates__(self):
        logger.info("IAM - List Server Certificates...")
        try:
            server_certificates = []
            for certificate in self.client.list_server_certificates()[
                "ServerCertificateMetadataList"
            ]:
                if not self.audit_resources or (
                    is_resource_filtered(certificate["Arn"], self.audit_resources)
                ):
                    server_certificates.append(
                        Certificate(
                            name=certificate["ServerCertificateName"],
                            id=certificate["ServerCertificateId"],
                            arn=certificate["Arn"],
                            expiration=certificate["Expiration"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return server_certificates

    def __list_tags_for_resource__(self):
        logger.info("IAM - List Tags...")
        try:
            for role in self.roles:
                try:
                    response = self.client.list_role_tags(RoleName=role.name)["Tags"]
                    role.tags = response
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntityException":
                        role.tags = []

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            for user in self.users:
                try:
                    response = self.client.list_user_tags(UserName=user.name)["Tags"]
                    user.tags = response
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntityException":
                        user.tags = []

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            for policy in self.policies:
                try:
                    response = self.client.list_policy_tags(PolicyArn=policy.arn)[
                        "Tags"
                    ]
                    policy.tags = response
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntityException":
                        policy.tags = []

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class MFADevice(BaseModel):
    serial_number: str
    type: str


class User(BaseModel):
    name: str
    arn: str
    mfa_devices: list[MFADevice] = []
    password_last_used: Optional[datetime]
    attached_policies: list[dict] = []
    inline_policies: list[str] = []
    tags: Optional[list] = []


class Role(BaseModel):
    name: str
    arn: str
    assume_role_policy: dict
    is_service_role: bool
    attached_policies: list[dict] = []
    tags: Optional[list] = []


class Group(BaseModel):
    name: str
    arn: str
    attached_policies: list[dict] = []
    users: list[User] = []


class PasswordPolicy(BaseModel):
    length: int
    symbols: bool
    numbers: bool
    uppercase: bool
    lowercase: bool
    allow_change: bool
    expiration: bool
    max_age: Optional[int]
    reuse_prevention: Optional[int]
    hard_expiry: Optional[bool]


class Certificate(BaseModel):
    name: str
    id: str
    arn: str
    expiration: datetime


class Policy(BaseModel):
    name: str
    arn: str
    version_id: str
    type: str
    attached: bool
    document: Optional[dict]
    tags: Optional[list] = []
