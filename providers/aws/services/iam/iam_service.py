import csv
import sys

from lib.logger import logger
from providers.aws.aws_provider import current_audit_info


################## IAM
class IAM:
    def __init__(self, audit_info):
        self.service = "iam"
        self.session = audit_info.audit_session
        self.client = self.session.client(self.service)
        self.region = audit_info.profile_region
        self.users = self.__get_users__()
        self.roles = self.__get_roles__()
        self.customer_managed_policies = self.__get_customer_managed_policies__()
        self.credential_report = self.__get_credential_report__()
        self.groups = self.__get_groups__()

    def __get_client__(self):
        return self.client

    def __get_session__(self):
        return self.session

    def __get_roles__(self):
        try:
            get_roles_paginator = self.client.get_paginator("list_roles")
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
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
                logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
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
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            groups = []
            for page in get_groups_paginator.paginate():
                for group in page["Groups"]:
                    groups.append(group)

            return groups

    def __get_customer_managed_policies__(self):
        try:
            get_customer_managed_policies_paginator = self.client.get_paginator(
                "list_policies"
            )
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            customer_managed_policies = []
            for page in get_customer_managed_policies_paginator.paginate(Scope="Local"):
                for customer_managed_policy in page["Policies"]:
                    customer_managed_policies.append(customer_managed_policy)

            return customer_managed_policies

    def __get_users__(self):
        try:
            get_users_paginator = self.client.get_paginator("list_users")
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            users = []
            for page in get_users_paginator.paginate():
                for user in page["Users"]:
                    users.append(user)

            return users

    def list_attached_group_policies(self, group):
        try:
            list_attached_group_policies_paginator = self.client.get_paginator(
                "list_attached_group_policies"
            )
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            attached_group_policies = []
            for page in list_attached_group_policies_paginator.paginate(
                GroupName=group
            ):
                for customer_managed_policy in page["AttachedPolicies"]:
                    attached_group_policies.append(customer_managed_policy)

            return attached_group_policies

    def get_group_users(self, group):
        try:
            get_group_paginator = self.client.get_paginator("get_group")
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            group_users = []
            for page in get_group_paginator.paginate(GroupName=group):
                for user in page["Users"]:
                    group_users.append(user)

            return group_users


try:
    iam_client = IAM(current_audit_info)
except Exception as error:
    logger.critical(f"{error.__class__.__name__} --  {error}")
    sys.exit()
