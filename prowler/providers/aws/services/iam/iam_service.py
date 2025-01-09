import csv
from datetime import datetime
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.config.config import encoding_format_utf_8
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


class IAM(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.role_arn_template = f"arn:{self.audited_partition}:iam:{self.region}:{self.audited_account}:role"
        self.password_policy_arn_template = f"arn:{self.audited_partition}:iam:{self.region}:{self.audited_account}:password-policy"
        self.mfa_arn_template = (
            f"arn:{self.audited_partition}:iam:{self.region}:{self.audited_account}:mfa"
        )
        self.users = self._get_users()
        self.roles = self._get_roles()
        self.account_summary = self._get_account_summary()
        self.virtual_mfa_devices = self._list_virtual_mfa_devices()
        self.credential_report = self._get_credential_report()
        self.groups = self._get_groups()
        self._get_group_users()
        self._list_attached_group_policies()
        self._list_attached_user_policies()
        self._list_attached_role_policies()
        self._list_mfa_devices()
        self.password_policy = self._get_password_policy()
        support_policy_arn = (
            f"arn:{self.audited_partition}:iam::aws:policy/AWSSupportAccess"
        )
        self.entities_role_attached_to_support_policy = (
            self._list_entities_role_for_policy(support_policy_arn)
        )
        securityaudit_policy_arn = (
            f"arn:{self.audited_partition}:iam::aws:policy/SecurityAudit"
        )
        self.entities_role_attached_to_securityaudit_policy = (
            self._list_entities_role_for_policy(securityaudit_policy_arn)
        )
        cloudshell_admin_policy_arn = (
            f"arn:{self.audited_partition}:iam::aws:policy/AWSCloudShellFullAccess"
        )
        self.entities_attached_to_cloudshell_policy = self._list_entities_for_policy(
            cloudshell_admin_policy_arn
        )
        # List both Customer (attached and unattached) and AWS Managed (only attached) policies
        self.policies = []
        self.policies.extend(self._list_policies("AWS"))
        self.policies.extend(self._list_policies("Local"))
        self._list_policies_version(self.policies)
        self._list_inline_user_policies()
        self._list_inline_group_policies()
        self._list_inline_role_policies()
        self.saml_providers = self._list_saml_providers()
        self.server_certificates = self._list_server_certificates()
        self.access_keys_metadata = {}
        self._get_access_keys_metadata()
        self.last_accessed_services = {}
        self._get_last_accessed_services()
        self.user_temporary_credentials_usage = {}
        self._get_user_temporary_credentials_usage()
        self.organization_features = []
        self._list_organizations_features()
        # List missing tags
        self.__threading_call__(self._list_tags, self.users)
        self.__threading_call__(self._list_tags, self.roles)
        self.__threading_call__(
            self._list_tags,
            [policy for policy in self.policies if policy.type == "Custom"],
        )
        self.__threading_call__(self._list_tags, self.server_certificates)
        if self.saml_providers is not None:
            self.__threading_call__(self._list_tags, self.saml_providers.values())

    def _get_client(self):
        return self.client

    def _get_roles(self):
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
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                roles = None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return roles

    def _get_credential_report(self):
        logger.info("IAM - Get Credential Report...")
        report_is_completed = False
        credential_list = []
        try:
            while not report_is_completed:
                report_status = self.client.generate_credential_report()
                if report_status["State"] == "COMPLETE":
                    report_is_completed = True
            # Convert credential report to list of dictionaries
            credential = self.client.get_credential_report()["Content"].decode(
                encoding_format_utf_8
            )
            credential_lines = credential.split("\n")
            csv_reader = csv.DictReader(credential_lines, delimiter=",")
            credential_list = list(csv_reader)

        except ClientError as error:
            if error.response["Error"]["Code"] == "LimitExceededException":
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
            return credential_list

    def _get_groups(self):
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

    def _get_account_summary(self):
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

    def _get_password_policy(self):
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

        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                # Password policy is the IAM default
                stored_password_policy = PasswordPolicy(
                    length=8,
                    symbols=False,
                    numbers=False,
                    uppercase=False,
                    lowercase=False,
                    allow_change=True,
                    expiration=False,
                    max_age=None,
                    reuse_prevention=None,
                    hard_expiry=None,
                )
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif error.response["Error"]["Code"] == "AccessDenied":
                # User does not have permission to get password policy
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                stored_password_policy = None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        finally:
            return stored_password_policy

    def _get_users(self):
        logger.info("IAM - List Users...")
        try:
            get_users_paginator = self.client.get_paginator("list_users")
            users = []
            for page in get_users_paginator.paginate():
                for user in page["Users"]:
                    if not self.audit_resources or (
                        is_resource_filtered(user["Arn"], self.audit_resources)
                    ):
                        try:
                            user_login_profile = self.client.get_login_profile(
                                UserName=user["UserName"]
                            )
                        except self.client.exceptions.NoSuchEntityException:
                            user_login_profile = None
                        except Exception as error:
                            user_login_profile = None
                            logger.error(
                                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )

                        users.append(
                            User(
                                name=user["UserName"],
                                arn=user["Arn"],
                                password_last_used=user.get("PasswordLastUsed", None),
                                console_access=True if user_login_profile else False,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return users

    def _list_virtual_mfa_devices(self):
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

    def _list_attached_group_policies(self):
        logger.info("IAM - List Attached Group Policies...")
        try:
            for group in self.groups:
                try:
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
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_group_users(self):
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

    def _list_mfa_devices(self):
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
                        try:
                            mfa_type = mfa_serial_number.split(":")[5].split("/")[0]
                        except IndexError:
                            mfa_type = "hardware"
                        mfa_devices.append(
                            MFADevice(serial_number=mfa_serial_number, type=mfa_type)
                        )
                user.mfa_devices = mfa_devices
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_attached_user_policies(self):
        logger.info("IAM - List Attached User Policies...")
        try:
            for user in self.users:
                try:
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

                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntity":
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
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_attached_role_policies(self):
        logger.info("IAM - List Attached User Policies...")
        try:
            if self.roles:
                for role in self.roles:
                    try:
                        attached_role_policies = []
                        list_attached_role_policies_paginator = (
                            self.client.get_paginator("list_attached_role_policies")
                        )
                        for page in list_attached_role_policies_paginator.paginate(
                            RoleName=role.name
                        ):
                            for policy in page["AttachedPolicies"]:
                                attached_role_policies.append(policy)

                        role.attached_policies = attached_role_policies
                    except ClientError as error:
                        if error.response["Error"]["Code"] == "NoSuchEntity":
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

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_inline_user_policies(self):
        logger.info("IAM - List Inline User Policies...")
        for user in self.users:
            try:
                inline_user_policies = []
                get_user_inline_policies_paginator = self.client.get_paginator(
                    "list_user_policies"
                )
                for page in get_user_inline_policies_paginator.paginate(
                    UserName=user.name
                ):
                    for policy in page["PolicyNames"]:
                        try:
                            inline_user_policies.append(policy)
                            # Get inline policies & their policy documents here
                            inline_policy = self.client.get_user_policy(
                                UserName=user.name, PolicyName=policy
                            )
                            inline_user_policy_doc = inline_policy["PolicyDocument"]
                            self.policies.append(
                                Policy(
                                    name=policy,
                                    arn=user.arn,
                                    entity=user.name,
                                    type="Inline",
                                    attached=True,
                                    version_id="v1",
                                    document=inline_user_policy_doc,
                                )
                            )
                        except ClientError as error:
                            if error.response["Error"]["Code"] == "NoSuchEntity":
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
                user.inline_policies = inline_user_policies
            except ClientError as error:
                if error.response["Error"]["Code"] == "NoSuchEntity":
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

    def _list_inline_group_policies(self):
        logger.info("IAM - List Inline Group Policies...")
        for group in self.groups:
            try:
                inline_group_policies = []
                get_group_inline_policies_paginator = self.client.get_paginator(
                    "list_group_policies"
                )
                for page in get_group_inline_policies_paginator.paginate(
                    GroupName=group.name
                ):
                    for policy in page["PolicyNames"]:
                        try:
                            inline_group_policies.append(policy)
                            # Get inline policies & their policy documents here:
                            inline_policy = self.client.get_group_policy(
                                GroupName=group.name, PolicyName=policy
                            )
                            inline_group_policy_doc = inline_policy["PolicyDocument"]
                            self.policies.append(
                                Policy(
                                    name=policy,
                                    arn=group.arn,
                                    entity=group.name,
                                    type="Inline",
                                    attached=True,
                                    version_id="v1",
                                    document=inline_group_policy_doc,
                                )
                            )
                        except ClientError as error:
                            if error.response["Error"]["Code"] == "NoSuchEntity":
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
                group.inline_policies = inline_group_policies
            except ClientError as error:
                if error.response["Error"]["Code"] == "NoSuchEntity":
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

    def _list_inline_role_policies(self):
        logger.info("IAM - List Inline Role Policies...")
        if self.roles:
            for role in self.roles:
                try:
                    inline_role_policies = []
                    get_role_inline_policies_paginator = self.client.get_paginator(
                        "list_role_policies"
                    )
                    for page in get_role_inline_policies_paginator.paginate(
                        RoleName=role.name
                    ):
                        for policy in page["PolicyNames"]:
                            try:
                                inline_role_policies.append(policy)
                                # Get inline policies & their policy documents here:
                                inline_policy = self.client.get_role_policy(
                                    RoleName=role.name, PolicyName=policy
                                )
                                inline_role_policy_doc = inline_policy["PolicyDocument"]
                                self.policies.append(
                                    Policy(
                                        name=policy,
                                        arn=role.arn,
                                        entity=role.name,
                                        type="Inline",
                                        attached=True,
                                        version_id="v1",
                                        document=inline_role_policy_doc,
                                    )
                                )
                            except ClientError as error:
                                if error.response["Error"]["Code"] == "NoSuchEntity":
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

                    role.inline_policies = inline_role_policies

                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntity":
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

    def _list_entities_role_for_policy(self, policy_arn):
        logger.info("IAM - List Entities Role For Policy...")
        try:
            roles = []
            roles = self.client.list_entities_for_policy(
                PolicyArn=policy_arn, EntityFilter="Role"
            )["PolicyRoles"]
            return roles
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                roles = None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return roles

    def _list_entities_for_policy(self, policy_arn):
        logger.info("IAM - List Entities Role For Policy...")
        try:
            entities = {
                "Users": [],
                "Groups": [],
                "Roles": [],
            }

            paginator = self.client.get_paginator("list_entities_for_policy")
            for response in paginator.paginate(PolicyArn=policy_arn):
                entities["Users"].extend(
                    user["UserName"] for user in response.get("PolicyUsers", [])
                )
                entities["Groups"].extend(
                    group["GroupName"] for group in response.get("PolicyGroups", [])
                )
                entities["Roles"].extend(
                    role["RoleName"] for role in response.get("PolicyRoles", [])
                )
            return entities
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                entities = None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return entities

    def _list_policies(self, scope):
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
                                entity=policy["PolicyId"],
                                version_id=policy["DefaultVersionId"],
                                type="Custom" if scope == "Local" else "AWS",
                                attached=(
                                    True if policy["AttachmentCount"] > 0 else False
                                ),
                            )
                        )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            return policies

    def _list_policies_version(self, policies):
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

    def _list_saml_providers(self):
        logger.info("IAM - List SAML Providers...")
        saml_providers = {}
        try:
            saml_providers_list = self.client.list_saml_providers()["SAMLProviderList"]

            for provider in saml_providers_list:
                if not self.audit_resources or (
                    is_resource_filtered(provider["Arn"], self.audit_resources)
                ):
                    saml_providers[provider["Arn"]] = SAMLProvider(
                        name=provider["Arn"].split("/")[-1], arn=provider["Arn"]
                    )
        except ClientError as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if error.response["Error"]["Code"] == "AccessDenied":
                saml_providers = None
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return saml_providers

    def _list_server_certificates(self) -> list:
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

    def _list_tags(self, resource: any):
        logger.info("IAM - List Tags...")
        try:
            if isinstance(resource, Role):
                resource.tags = self.client.list_role_tags(RoleName=resource.name).get(
                    "Tags", []
                )
            elif isinstance(resource, User):
                resource.tags = self.client.list_user_tags(UserName=resource.name).get(
                    "Tags", []
                )
            elif isinstance(resource, Policy):
                if resource.type == "Custom":
                    resource.tags = self.client.list_policy_tags(
                        PolicyArn=resource.arn
                    ).get("Tags", [])
            elif isinstance(resource, Certificate):
                resource.tags = self.client.list_server_certificate_tags(
                    ServerCertificateName=resource.name
                ).get("Tags", [])
            elif isinstance(resource, SAMLProvider):
                resource.tags = self.client.list_saml_provider_tags(
                    SAMLProviderArn=resource.arn
                ).get("Tags", [])
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_last_accessed_services(self):
        logger.info("IAM - Getting Last Accessed Services ...")
        try:
            for user in self.users:
                try:
                    details = self.client.generate_service_last_accessed_details(
                        Arn=user.arn
                    )
                    response = self.client.get_service_last_accessed_details(
                        JobId=details["JobId"]
                    )
                    while response["JobStatus"] == "IN_PROGRESS":
                        response = self.client.get_service_last_accessed_details(
                            JobId=details["JobId"]
                        )
                    self.last_accessed_services[(user.name, user.arn)] = response.get(
                        "ServicesLastAccessed", {}
                    )

                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntity":
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

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_access_keys_metadata(self):
        logger.info("IAM - Getting Access Keys Metadata ...")
        try:
            for user in self.users:
                try:
                    paginator = self.client.get_paginator("list_access_keys")
                    self.access_keys_metadata[(user.name, user.arn)] = []
                    for response in paginator.paginate(UserName=user.name):
                        self.access_keys_metadata[(user.name, user.arn)] = response[
                            "AccessKeyMetadata"
                        ]
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchEntity":
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
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_user_temporary_credentials_usage(self):
        logger.info("IAM - Getting User Temporary Credentials Usage ...")
        try:
            temporary_credentials_usage = False
            for (
                user_data,
                last_accessed_services,
            ) in self.last_accessed_services.items():
                # Get AWS services number used more than IAM and STS
                services_accessed = len(
                    [
                        service
                        for service in last_accessed_services
                        if service["ServiceNamespace"] not in ["iam", "sts"]
                    ]
                )
                # Get IAM user access keys number
                access_keys_number = len(self.access_keys_metadata[user_data])

                # If the user has access keys and uses more services than IAM and STS store True, otherwise False
                temporary_credentials_usage = (
                    services_accessed > 0 and access_keys_number > 0
                )

                self.user_temporary_credentials_usage[user_data] = (
                    temporary_credentials_usage
                )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_organizations_features(self):
        logger.info("IAM - List Organization Features...")
        try:
            organization_features = self.client.list_organizations_features()
            self.organization_features = organization_features.get(
                "EnabledFeatures", []
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "OrganizationNotFoundException":
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif error.response["Error"]["Code"] == "ServiceAccessNotEnabledException":
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif (
                error.response["Error"]["Code"]
                == "OrganizationNotInAllFeaturesModeException"
            ):
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif (
                error.response["Error"]["Code"]
                == "AccountNotManagementOrDelegatedAdministratorException"
            ):
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                self.organization_features = None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
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
    console_access: Optional[bool]
    attached_policies: list[dict] = []
    inline_policies: list[str] = []
    tags: Optional[list]


class Role(BaseModel):
    name: str
    arn: str
    assume_role_policy: dict
    is_service_role: bool
    attached_policies: list[dict] = []
    inline_policies: list[str] = []
    tags: Optional[list]


class Group(BaseModel):
    name: str
    arn: str
    attached_policies: list[dict] = []
    inline_policies: list[str] = []
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
    tags: Optional[list]


class Policy(BaseModel):
    name: str
    arn: str
    entity: str
    version_id: str
    type: str
    attached: bool
    document: Optional[dict]
    tags: Optional[list] = []


class SAMLProvider(BaseModel):
    name: str
    arn: str
    tags: Optional[list]
