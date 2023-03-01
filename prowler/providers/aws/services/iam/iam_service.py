import csv
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


def is_service_role(role):
    if "Statement" in role["AssumeRolePolicyDocument"]:
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
    return False


################## IAM
class IAM:
    def __init__(self, audit_info):
        self.service = "iam"
        self.session = audit_info.audit_session
        self.account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.partition = audit_info.audited_partition
        self.client = self.session.client(self.service)
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        self.client = list(global_client.values())[0]
        self.region = self.client.region
        self.users = self.__get_users__()
        self.roles = self.__get_roles__()
        self.account_summary = self.__get_account_summary__()
        self.virtual_mfa_devices = self.__list_virtual_mfa_devices__()
        self.credential_report = self.__get_credential_report__()
        self.groups = self.__get_groups__()
        self.__get_group_users__()
        self.__list_attached_group_policies__()
        self.__list_attached_user_policies__()
        self.__list_inline_user_policies__()
        self.__list_mfa_devices__()
        self.password_policy = self.__get_password_policy__()
        self.entities_attached_to_support_roles = (
            self.__get_entities_attached_to_support_roles__()
        )
        self.policies = self.__list_policies__()
        self.__list_policies_version__(self.policies)
        self.saml_providers = self.__list_saml_providers__()
        self.server_certificates = self.__list_server_certificates__()

    def __get_client__(self):
        return self.client

    def __get_session__(self):
        return self.session

    def __get_roles__(self):
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
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return credential_list

    def __get_groups__(self):
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
        try:
            account_summary = self.client.get_account_summary()
            return account_summary
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_password_policy__(self):
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
                expiration=password_policy["RequireNumbers"],
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
        try:
            list_virtual_mfa_devices_paginator = self.client.get_paginator(
                "list_virtual_mfa_devices"
            )
            mfa_devices = []
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

    def __list_inline_user_policies__(self):
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

    def __get_entities_attached_to_support_roles__(self):
        try:
            support_roles = []
            support_entry_policy_arn = (
                "arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"
            )
            support_roles = self.client.list_entities_for_policy(
                PolicyArn=support_entry_policy_arn, EntityFilter="Role"
            )["PolicyRoles"]
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return support_roles

    def __list_policies__(self):
        try:
            policies = []
            list_policies_paginator = self.client.get_paginator("list_policies")
            for page in list_policies_paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    if not self.audit_resources or (
                        is_resource_filtered(policy["Arn"], self.audit_resources)
                    ):
                        policies.append(policy)
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return policies

    def __list_policies_version__(self, policies):
        try:
            pass

            for policy in policies:
                policy_version = self.client.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )
                policy["PolicyDocument"] = policy_version["PolicyVersion"]["Document"]
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_saml_providers__(self):
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


class MFADevice(BaseModel):
    serial_number: str
    type: str


class User(BaseModel):
    name: str
    arn: str
    mfa_devices: list[MFADevice] = []
    password_last_used: Optional[Any]
    attached_policies: list[dict] = []
    inline_policies: list[str] = []


class Role(BaseModel):
    name: str
    arn: str
    assume_role_policy: dict
    is_service_role: bool


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
    max_age: Optional[Any]
    reuse_prevention: Optional[Any]
    hard_expiry: Optional[Any]


class Certificate(BaseModel):
    name: str
    id: str
    arn: str
    expiration: datetime
