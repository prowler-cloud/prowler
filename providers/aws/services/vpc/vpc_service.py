import threading
from dataclasses import dataclass

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################## VPC
class VPC:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.vpcs = []
        self.__threading_call__(self.__describe_vpcs__)
        self.__describe_flow_logs__()

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_vpcs__(self, regional_client):
        logger.info("VPC - Describing VPCs...")
        try:
            describe_vpcs_paginator = regional_client.get_paginator("describe_vpcs")
            for page in describe_vpcs_paginator.paginate():
                for vpc in page["Vpcs"]:
                    self.vpcs.append(
                        VPCs(
                            vpc["VpcId"],
                            vpc["IsDefault"],
                            vpc["CidrBlock"],
                            regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __describe_flow_logs__(self):
        logger.info("VPC - Describing flow logs...")
        try:
            for vpc in self.vpcs:
                regional_client = self.regional_clients[vpc.region]
                flow_logs = regional_client.describe_flow_logs(
                    Filters=[
                        {
                            "Name": "resource-id",
                            "Values": [
                                vpc.id,
                            ],
                        },
                    ]
                )["FlowLogs"]
                if flow_logs:
                    vpc.flow_log = True
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")


@dataclass
class VPCs:
    id: str
    default: bool
    cidr_block: str
    flow_log: bool
    region: str

    def __init__(
        self,
        id,
        default,
        cidr_block,
        region,
    ):
        self.id = id
        self.default = default
        self.cidr_block = cidr_block
        self.flow_log = False
        self.region = region
