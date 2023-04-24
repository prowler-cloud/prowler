import threading

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients

################## DRS (Elastic Disaster Recovery Service)


class DRS:
    def __init__(self, audit_info):
        self.service = "drs"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audited_partition = audit_info.audited_partition
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        # If the region is not set in the audit profile,
        # we pick the first region from the regional clients list
        self.region = (
            audit_info.profile_region
            if audit_info.profile_region
            else list(self.regional_clients.keys())[0]
        )
        self.drss = []
        self.drs_jobs = []
        self.__threading_call__(self.__describe_jobs__)

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

    def __describe_jobs__(self, regional_client):
        logger.info("DRS - Describe Jobs...")
        try:
            try:
                describe_jobs_paginator = regional_client.get_paginator("describe_jobs")
                for page in describe_jobs_paginator.paginate():
                    drs_jobs = []
                    for drs_job in page["items"]:
                        if not self.audit_resources or (
                            is_resource_filtered(drs_job["arn"], self.audit_resources)
                        ):
                            job = Job(
                                arn=drs_job.get("arn"),
                                id=drs_job.get("jobID"),
                                region=regional_client.region,
                                status=drs_job.get("status"),
                                tags=[drs_job.get("tags")],
                            )
                            self.drs_jobs.append(job)
                            drs_jobs.append(job)
                    self.drss.append(
                        DRSservice(
                            id="DRS",
                            status="ENABLED",
                            region=regional_client.region,
                            jobs=drs_jobs,
                        )
                    )
            except ClientError as error:
                if error.response["Error"]["Code"] == "UninitializedAccountException":
                    self.drss.append(
                        DRSservice(id="DRS", status="DISABLED", region=regional_client.region)
                    )
                else:
                    logger.error(
                        f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class Job(BaseModel):
    arn: str
    id: str
    status: str
    region: str
    tags: list = []


class DRSservice(BaseModel):
    id: str
    status: str
    region: str
    jobs: list[Job] = []
