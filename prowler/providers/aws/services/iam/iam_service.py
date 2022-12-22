import csv
from dataclasses import dataclass
from datetime import datetime

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## IAM
class IAM:
    def __init__(self, audit_info):
        self.service = "iam"
        self.session = audit_info.audit_session
        self.account = audit_info.audited_account
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
        self.customer_managed_policies = self.__get_customer_managed_policies__()
        self.__get_customer_managed_policies_version__(self.customer_managed_policies)
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
        self.list_policies_version = self.__list_policies_version__(self.policies)
        self.saml_providers = self.__list_saml_providers__()
        self.server_certificates = self.__list_server_certificates__()

    def __get_client__(self):
        return self.client

    def __get_session__(self):
        return self.session

    def __get_roles__(self):
        try:
            get_roles_paginator = self.client.get_paginator("list_roles")
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            roles = []
            for page in get_roles_paginator.paginate():
                for role in page["Roles"]:
                    roles.append(role)

            return roles

    def __get_credential_report__(self):
        report_is_completed = False
        while not report_is_completed:
            try:
                report_status = self.client.generate_credential_report()
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                if report_status["State"] == "COMPLETE":
                    report_is_completed = True

        # Convert credential report to list of dictionaries
        credential = self.client.get_credential_report()["Content"].decode("utf-8")
        credential_lines = credential.split("\n")
        csv_reader = csv.DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)
        return credential_list

    def __get_groups__(self):
        try:
            get_groups_paginator = self.client.get_paginator("list_groups")
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            groups = []
            for page in get_groups_paginator.paginate():
                for group in page["Groups"]:
                    groups.append(Group(group["GroupName"], group["Arn"]))

            return groups

    def __get_customer_managed_policies__(self):
        try:
            get_customer_managed_policies_paginator = self.client.get_paginator(
                "list_policies"
            )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            customer_managed_policies = []
            # Use --scope Local to list only Customer Managed Policies
            for page in get_customer_managed_policies_paginator.paginate(Scope="Local"):
                for customer_managed_policy in page["Policies"]:
                    customer_managed_policies.append(customer_managed_policy)

            return customer_managed_policies

    def __get_customer_managed_policies_version__(self, customer_managed_policies):
        try:
            for policy in customer_managed_policies:
                response = self.client.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )
                policy["PolicyDocument"] = response["PolicyVersion"]["Document"]
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_account_summary__(self):
        try:
            account_summary = self.client.get_account_summary()
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:

            return account_summary

    def __get_password_policy__(self):
        try:
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
        except Exception as error:
            if "NoSuchEntity" in str(error):
                # Password policy does not exist
                password_policy = None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        else:
            return PasswordPolicy(
                password_policy["MinimumPasswordLength"],
                password_policy["RequireSymbols"],
                password_policy["RequireNumbers"],
                password_policy["RequireUppercaseCharacters"],
                password_policy["RequireLowercaseCharacters"],
                password_policy["AllowUsersToChangePassword"],
                password_policy["ExpirePasswords"],
                max_age,
                reuse_prevention,
                hard_expiry,
            )

    def __get_users__(self):
        try:
            get_users_paginator = self.client.get_paginator("list_users")
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            users = []
            for page in get_users_paginator.paginate():
                for user in page["Users"]:
                    if "PasswordLastUsed" not in user:
                        users.append(User(user["UserName"], user["Arn"], None))
                    else:
                        users.append(
                            User(
                                user["UserName"], user["Arn"], user["PasswordLastUsed"]
                            )
                        )

            return users

    def __list_virtual_mfa_devices__(self):
        try:
            list_virtual_mfa_devices_paginator = self.client.get_paginator(
                "list_virtual_mfa_devices"
            )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            mfa_devices = []
            for page in list_virtual_mfa_devices_paginator.paginate():
                for mfa_device in page["VirtualMFADevices"]:
                    mfa_devices.append(mfa_device)

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
                                User(user["UserName"], user["Arn"], None)
                            )
                        else:
                            group_users.append(
                                User(
                                    user["UserName"],
                                    user["Arn"],
                                    user["PasswordLastUsed"],
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
                        mfa_devices.append(MFADevice(mfa_serial_number, mfa_type))
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
                    policies.append(policy)
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return policies

    def __list_policies_version__(self, policies):
        try:
            policies_version = []

            for policy in policies:
                policy_version = self.client.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )
                policies_version.append(policy_version["PolicyVersion"]["Document"])
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return policies_version

    def __list_saml_providers__(self):
        try:
            saml_providers = self.client.list_saml_providers()["SAMLProviderList"]
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        finally:
            return saml_providers

    def __list_server_certificates__(self):
        try:
            server_certificates = []
            for certificate in self.client.list_server_certificates()[
                "ServerCertificateMetadataList"
            ]:
                server_certificates.append(
                    Certificate(
                        certificate["ServerCertificateName"],
                        certificate["ServerCertificateId"],
                        certificate["Arn"],
                        certificate["Expiration"],
                    )
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        finally:
            return server_certificates


@dataclass
class MFADevice:
    serial_number: str
    type: str

    def __init__(self, serial_number, type):
        self.serial_number = serial_number
        self.type = type


@dataclass
class User:
    name: str
    arn: str
    mfa_devices: list[MFADevice]
    password_last_used: str
    attached_policies: list[dict]
    inline_policies: list[str]

    def __init__(self, name, arn, password_last_used):
        self.name = name
        self.arn = arn
        self.password_last_used = password_last_used
        self.mfa_devices = []
        self.attached_policies = []
        self.inline_policies = []


@dataclass
class Group:
    name: str
    arn: str
    attached_policies: list[dict]
    users: list[User]

    def __init__(self, name, arn):
        self.name = name
        self.arn = arn
        self.attached_policies = []
        self.users = []


@dataclass
class PasswordPolicy:
    length: int
    symbols: bool
    numbers: bool
    uppercase: bool
    lowercase: bool
    allow_change: bool
    expiration: bool
    max_age: int
    reuse_prevention: int
    hard_expiry: bool

    def __init__(
        self,
        length,
        symbols,
        numbers,
        uppercase,
        lowercase,
        allow_change,
        expiration,
        max_age,
        reuse_prevention,
        hard_expiry,
    ):
        self.length = length
        self.symbols = symbols
        self.numbers = numbers
        self.uppercase = uppercase
        self.lowercase = lowercase
        self.allow_change = allow_change
        self.expiration = expiration
        self.max_age = max_age
        self.reuse_prevention = reuse_prevention
        self.hard_expiry = hard_expiry


@dataclass
class Certificate:
    name: str
    id: str
    arn: str
    expiration: datetime

    def __init__(self, name, id, arn, expiration):
        self.name = name
        self.id = id
        self.arn = arn
        self.expiration = expiration
