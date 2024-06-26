from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## DRS (Elastic Disaster Recovery Service)
class DRS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.drs_services = []
        self.__threading_call__(self.__describe_jobs__)

    def __get_recovery_job_arn_template__(self, region):
        return f"arn:{self.audited_partition}:drs:{region}:{self.audited_account}:recovery-job"

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
                            drs_jobs.append(job)
                    self.drs_services.append(
                        DRSservice(
                            id="DRS",
                            status="ENABLED",
                            region=regional_client.region,
                            jobs=drs_jobs,
                        )
                    )
            except ClientError as error:
                if error.response["Error"]["Code"] == "UninitializedAccountException":
                    self.drs_services.append(
                        DRSservice(
                            id="DRS", status="DISABLED", region=regional_client.region
                        )
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
