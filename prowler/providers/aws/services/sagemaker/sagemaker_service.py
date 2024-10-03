from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ SageMaker
class SageMaker(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.sagemaker_notebook_instances = []
        self.sagemaker_models = []
        self.sagemaker_training_jobs = []
        self.endpoint_configs = {}
        self.__threading_call__(self._list_notebook_instances)
        self.__threading_call__(self._list_models)
        self.__threading_call__(self._list_training_jobs)
        self.__threading_call__(self._list_endpoint_configs)
        self.__threading_call__(self._describe_model, self.sagemaker_models)
        self.__threading_call__(
            self._describe_notebook_instance, self.sagemaker_notebook_instances
        )
        self.__threading_call__(
            self._describe_training_job, self.sagemaker_training_jobs
        )
        self.__threading_call__(
            self._describe_endpoint_config, self.endpoint_configs.values()
        )
        self._list_tags_for_resource()

    def _list_notebook_instances(self, regional_client):
        logger.info("SageMaker - listing notebook instances...")
        try:
            list_notebook_instances_paginator = regional_client.get_paginator(
                "list_notebook_instances"
            )
            for page in list_notebook_instances_paginator.paginate():
                for notebook_instance in page["NotebookInstances"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            notebook_instance["NotebookInstanceArn"],
                            self.audit_resources,
                        )
                    ):
                        self.sagemaker_notebook_instances.append(
                            NotebookInstance(
                                name=notebook_instance["NotebookInstanceName"],
                                region=regional_client.region,
                                arn=notebook_instance["NotebookInstanceArn"],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_models(self, regional_client):
        logger.info("SageMaker - listing models...")
        try:
            list_models_paginator = regional_client.get_paginator("list_models")
            for page in list_models_paginator.paginate():
                for model in page["Models"]:
                    if not self.audit_resources or (
                        is_resource_filtered(model["ModelArn"], self.audit_resources)
                    ):
                        self.sagemaker_models.append(
                            Model(
                                name=model["ModelName"],
                                region=regional_client.region,
                                arn=model["ModelArn"],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_training_jobs(self, regional_client):
        logger.info("SageMaker - listing training jobs...")
        try:
            list_training_jobs_paginator = regional_client.get_paginator(
                "list_training_jobs"
            )
            for page in list_training_jobs_paginator.paginate():
                for training_job in page["TrainingJobSummaries"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            training_job["TrainingJobArn"], self.audit_resources
                        )
                    ):
                        self.sagemaker_training_jobs.append(
                            TrainingJob(
                                name=training_job["TrainingJobName"],
                                region=regional_client.region,
                                arn=training_job["TrainingJobArn"],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_notebook_instance(self, notebook_instance):
        logger.info("SageMaker - describing notebook instances...")
        try:
            regional_client = self.regional_clients[notebook_instance.region]
            try:
                describe_notebook_instance = regional_client.describe_notebook_instance(
                    NotebookInstanceName=notebook_instance.name
                )
            except ClientError as error:
                if error.response["Error"]["Code"] == "ValidationException":
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            if (
                "RootAccess" in describe_notebook_instance
                and describe_notebook_instance["RootAccess"] == "Enabled"
            ):
                notebook_instance.root_access = True
            if "SubnetId" in describe_notebook_instance:
                notebook_instance.subnet_id = describe_notebook_instance["SubnetId"]
            if (
                "DirectInternetAccess" in describe_notebook_instance
                and describe_notebook_instance["RootAccess"] == "Enabled"
            ):
                notebook_instance.direct_internet_access = True
            if "KmsKeyId" in describe_notebook_instance:
                notebook_instance.kms_key_id = describe_notebook_instance["KmsKeyId"]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_model(self, model):
        logger.info("SageMaker - describing models...")
        try:
            regional_client = self.regional_clients[model.region]
            describe_model = regional_client.describe_model(ModelName=model.name)
            if "EnableNetworkIsolation" in describe_model:
                model.network_isolation = describe_model["EnableNetworkIsolation"]
            if (
                "VpcConfig" in describe_model
                and "Subnets" in describe_model["VpcConfig"]
            ):
                model.vpc_config_subnets = describe_model["VpcConfig"]["Subnets"]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_training_job(self, training_job):
        logger.info("SageMaker - describing training jobs...")
        try:
            regional_client = self.regional_clients[training_job.region]
            describe_training_job = regional_client.describe_training_job(
                TrainingJobName=training_job.name
            )
            if "EnableInterContainerTrafficEncryption" in describe_training_job:
                training_job.container_traffic_encryption = describe_training_job[
                    "EnableInterContainerTrafficEncryption"
                ]
            if (
                "ResourceConfig" in describe_training_job
                and "VolumeKmsKeyId" in describe_training_job["ResourceConfig"]
            ):
                training_job.volume_kms_key_id = describe_training_job[
                    "ResourceConfig"
                ]["VolumeKmsKeyId"]
            if "EnableNetworkIsolation" in describe_training_job:
                training_job.network_isolation = describe_training_job[
                    "EnableNetworkIsolation"
                ]
            if (
                "VpcConfig" in describe_training_job
                and "Subnets" in describe_training_job["VpcConfig"]
            ):
                training_job.vpc_config_subnets = describe_training_job["VpcConfig"][
                    "Subnets"
                ]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("SageMaker - List Tags...")
        try:
            for model in self.sagemaker_models:
                regional_client = self.regional_clients[model.region]
                response = regional_client.list_tags(ResourceArn=model.arn)["Tags"]
                model.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        try:
            for instance in self.sagemaker_notebook_instances:
                regional_client = self.regional_clients[instance.region]
                response = regional_client.list_tags(ResourceArn=instance.arn)["Tags"]
                instance.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        try:
            for job in self.sagemaker_training_jobs:
                regional_client = self.regional_clients[job.region]
                response = regional_client.list_tags(ResourceArn=job.arn)["Tags"]
                job.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        try:
            for endpoint in self.endpoint_configs.values():
                regional_client = self.regional_clients[endpoint.region]
                response = regional_client.list_tags(ResourceArn=endpoint.arn)["Tags"]
                endpoint.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_endpoint_configs(self, regional_client):
        logger.info("SageMaker - listing endpoint configs...")
        try:
            list_endpoint_config_paginator = regional_client.get_paginator(
                "list_endpoint_configs"
            )
            for page in list_endpoint_config_paginator.paginate():
                for endpoint_config in page["EndpointConfigs"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            endpoint_config["EndpointConfigArn"], self.audit_resources
                        )
                    ):
                        self.endpoint_configs[endpoint_config["EndpointConfigArn"]] = (
                            EndpointConfig(
                                name=endpoint_config["EndpointConfigName"],
                                region=regional_client.region,
                                arn=endpoint_config["EndpointConfigArn"],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_endpoint_config(self, endpoint_config):
        logger.info("SageMaker - describing endpoint configs...")
        try:
            regional_client = self.regional_clients[endpoint_config.region]
            describe_endpoint_config = regional_client.describe_endpoint_config(
                EndpointConfigName=endpoint_config.name
            )
            production_variants = []
            for production_variant in describe_endpoint_config["ProductionVariants"]:
                production_variants.append(
                    ProductionVariant(
                        name=production_variant["VariantName"],
                        initial_instance_count=production_variant[
                            "InitialInstanceCount"
                        ],
                    )
                )
            endpoint_config.production_variants = production_variants
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class NotebookInstance(BaseModel):
    name: str
    region: str
    arn: str
    root_access: bool = None
    subnet_id: str = None
    direct_internet_access: bool = None
    kms_key_id: str = None
    tags: Optional[list] = []


class Model(BaseModel):
    name: str
    region: str
    arn: str
    network_isolation: bool = None
    vpc_config_subnets: list[str] = []
    tags: Optional[list] = []


class TrainingJob(BaseModel):
    name: str
    region: str
    arn: str
    container_traffic_encryption: bool = None
    volume_kms_key_id: str = None
    network_isolation: bool = None
    vpc_config_subnets: list[str] = []
    tags: Optional[list] = []


class ProductionVariant(BaseModel):
    name: str
    initial_instance_count: int


class EndpointConfig(BaseModel):
    name: str
    region: str
    arn: str
    production_variants: list[ProductionVariant] = []
    tags: Optional[list] = []
