import threading

from lib.logger import logger
from providers.aws.aws_provider import current_audit_info, generate_regional_clients


################## EC2
class EC2:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.__threading_call__(self.__describe_snapshots__)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients:
            threads.append(
                threading.Thread(
                    target=call, args=(regional_client, self.audited_account)
                )
            )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_snapshots__(self, regional_client, audited_account):
        logger.info("EC2 - Describing Snapshots...")
        try:
            describe_snapshots_paginator = regional_client.get_paginator(
                "describe_snapshots"
            )
            snapshots = []
            for page in describe_snapshots_paginator.paginate(
                OwnerIds=[audited_account]
            ):
                for snapshot in page["Snapshots"]:
                    snapshots.append(snapshot)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )
        else:
            regional_client.snapshots = snapshots


ec2_client = EC2(current_audit_info)
