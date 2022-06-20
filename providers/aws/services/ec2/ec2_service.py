import json
import threading
import urllib.request

from config.config import aws_services_json_file, aws_services_json_url
from lib.logger import logger
from lib.utils.utils import open_file, parse_json_file
from providers.aws.aws_provider import (
    audited_account,
    audited_partition,
    audited_regions,
    aws_session,
)


################## EC2
class EC2:
    def __init__(self, aws_session, audited_regions):
        self.service = "ec2"
        self.aws_session = aws_session
        self.regional_clients = self.__generate_regional_clients__(
            self.service, audited_regions
        )
        self.__threading_call__(self.__describe_snapshots__)

    def __get_clients__(self):
        return self.clients

    def __get_session__(self):
        return self.aws_session

    def __generate_regional_clients__(self, service, audited_regions):
        regional_clients = []
        try:  # Try to get the list online
            with urllib.request.urlopen(aws_services_json_url) as url:
                data = json.loads(url.read().decode())
        except:
            # Get the list locally
            f = open_file(aws_services_json_file)
            data = parse_json_file(f)

        for att in data["prices"]:
            if audited_regions:  # Check for input aws audited_regions
                if (
                    service in att["id"].split(":")[0]
                    and att["attributes"]["aws:region"] in audited_regions
                ):  # Check if service has this region
                    region = att["attributes"]["aws:region"]
                    regional_client = aws_session.client(service, region_name=region)
                    regional_client.region = region
                    regional_clients.append(regional_client)
            else:
                if audited_partition in "aws":
                    if (
                        service in att["id"].split(":")[0]
                        and "gov" not in att["attributes"]["aws:region"]
                        and "cn" not in att["attributes"]["aws:region"]
                    ):
                        region = att["attributes"]["aws:region"]
                        regional_client = aws_session.client(
                            service, region_name=region
                        )
                        regional_client.region = region
                        regional_clients.append(regional_client)
                elif audited_partition in "cn":
                    if (
                        service in att["id"].split(":")[0]
                        and "cn" in att["attributes"]["aws:region"]
                    ):
                        region = att["attributes"]["aws:region"]
                        regional_client = aws_session.client(
                            service, region_name=region
                        )
                        regional_client.region = region
                        regional_clients.append(regional_client)
                elif audited_partition in "gov":
                    if (
                        service in att["id"].split(":")[0]
                        and "gov" in att["attributes"]["aws:region"]
                    ):
                        region = att["attributes"]["aws:region"]
                        regional_client = aws_session.client(
                            service, region_name=region
                        )
                        regional_client.region = region
                        regional_clients.append(regional_client)

        return regional_clients

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients:
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_snapshots__(self, regional_client):
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


ec2_client = EC2(aws_session, audited_regions)
