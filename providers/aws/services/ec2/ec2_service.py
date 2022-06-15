import botocore
from boto3 import session
from lib.logger import logger
import threading

from providers.aws.aws_provider import session, generate_clients, account


################## EC2
class EC2:
    def __init__(self, session):
        self.client = [] 
        self.service = "ec2"
        self.session = session
        self.client = generate_clients(self.service)
        self.snapshots = []
        self.threading_call(self.__describe_snapshots__)

    def __get_client__(self):
        return self.client

    def __get_session__(self):
        return self.session
    
    def threading_call(self,call):
        threads = []
        for client in self.client:
            threads.append(threading.Thread(target=call,args=(client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_snapshots__(self,client):
        logger.info("EC2 - Describing Snapshots...")
        try:
            describe_snapshots_paginator = client['client'].get_paginator("describe_snapshots")
            snapshots = []
            for page in describe_snapshots_paginator.paginate(OwnerIds=[account]):
                for snapshot in page["Snapshots"]:
                    snapshots.append(snapshot)
            client["response"] = snapshots
        except botocore.exceptions.ClientError as error:
            client["response"] = str(error)
        self.snapshots.append(client)

ec2_client = EC2(session)
