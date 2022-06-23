import threading

from config.config import aws_services_json_file
from lib.logger import logger
from lib.utils.utils import open_file, parse_json_file
from providers.aws.aws_provider import current_audit_info


################## EC2
class EC2:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = self.__generate_regional_clients__(
            self.service, audit_info
        )
        self.__threading_call__(self.__describe_snapshots__)

    def __get_session__(self):
        return self.session

    def __generate_regional_clients__(self, service, audit_info):
        regional_clients = []
        # Get json locally
        f = open_file(aws_services_json_file)
        data = parse_json_file(f)
        json_regions = data["services"][service]["regions"][
            audit_info.audited_partition
        ]
        if audit_info.audited_regions:  # Check for input aws audit_info.audited_regions
            regions = list(
                set(json_regions).intersection(audit_info.audited_regions)
            )  # Get common regions between input and json
        else:  # Get all regions from json of the service and partition
            regions = json_regions
        for region in regions:
            regional_client = audit_info.audit_session.client(
                service, region_name=region
            )
            regional_client.region = region
            regional_clients.append(regional_client)

        return regional_clients

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
            logger.error(f"{error.__class__.__name__} -- {error}")
        else:
            regional_client.snapshots = snapshots


ec2_client = EC2(current_audit_info)
