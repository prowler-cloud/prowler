from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWS_Service


################### GlobalAccelerator
class GlobalAccelerator(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__(__class__.__name__, audit_info)
        self.accelerators = {}
        if audit_info.audited_partition == "aws":
            # Global Accelerator is a global service that supports endpoints in multiple AWS Regions
            # but you must specify the US West (Oregon) Region to create, update, or otherwise work with accelerators.
            # That is, for example, specify --region us-west-2 on AWS CLI commands.
            self.region = "us-west-2"
            self.client = self.session.client(self.service, self.region)
            self.__list_accelerators__()

    def __list_accelerators__(self):
        logger.info("GlobalAccelerator - Listing Accelerators...")
        try:
            list_accelerators_paginator = self.client.get_paginator("list_accelerators")
            for page in list_accelerators_paginator.paginate():
                for accelerator in page["Accelerators"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            accelerator["AcceleratorArn"], self.audit_resources
                        )
                    ):
                        accelerator_arn = accelerator["AcceleratorArn"]
                        accelerator_name = accelerator["Name"]
                        enabled = accelerator["Enabled"]
                        # We must use the Accelerator ARN as the dict key to have unique keys
                        self.accelerators[accelerator_arn] = Accelerator(
                            name=accelerator_name,
                            arn=accelerator_arn,
                            region=self.region,
                            enabled=enabled,
                        )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Accelerator(BaseModel):
    arn: str
    name: str
    region: str
    enabled: bool
