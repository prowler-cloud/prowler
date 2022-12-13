import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ SageMaker
class SageMaker:
    def __init__(self, audit_info):
        self.service = "sagemaker"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.sagemaker_notebook_instances = []
        self.sagemaker_models = []
        self.sagemaker_training_jobs = []
        self.__threading_call__(self.__list_notebook_instances__)
        self.__threading_call__(self.__list_models__)
        self.__threading_call__(self.__list_training_jobs__)
        self.__describe_model__(self.regional_clients)
        self.__describe_notebook_instance__(self.regional_clients)
        self.__describe_training_job__(self.regional_clients)

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

    def __list_notebook_instances__(self, regional_client):
        logger.info("SageMaker - listing notebook instances...")
        try:
            list_notebook_instances_paginator = regional_client.get_paginator(
                "list_notebook_instances"
            )
            for page in list_notebook_instances_paginator.paginate():
                for notebook_instance in page["NotebookInstances"]:
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

    def __list_models__(self, regional_client):
        logger.info("SageMaker - listing models...")
        try:
            list_models_paginator = regional_client.get_paginator("list_models")
            for page in list_models_paginator.paginate():
                for model in page["Models"]:
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

    def __list_training_jobs__(self, regional_client):
        logger.info("SageMaker - listing training jobs...")
        try:
            list_training_jobs_paginator = regional_client.get_paginator(
                "list_training_jobs"
            )
            for page in list_training_jobs_paginator.paginate():
                for training_job in page["TrainingJobSummaries"]:
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

    def __describe_notebook_instance__(self, regional_clients):
        logger.info("SageMaker - describing notebook instances...")
        try:
            for notebook_instance in self.sagemaker_notebook_instances:
                regional_client = regional_clients[notebook_instance.region]
                describe_notebook_instance = regional_client.describe_notebook_instance(
                    NotebookInstanceName=notebook_instance.name
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
                    notebook_instance.kms_key_id = describe_notebook_instance[
                        "KmsKeyId"
                    ]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_model__(self, regional_clients):
        logger.info("SageMaker - describing models...")
        try:
            for model in self.sagemaker_models:
                regional_client = regional_clients[model.region]
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

    def __describe_training_job__(self, regional_clients):
        logger.info("SageMaker - describing training jobs...")
        try:
            for training_job in self.sagemaker_training_jobs:
                regional_client = regional_clients[training_job.region]
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
                    training_job.vpc_config_subnets = describe_training_job[
                        "VpcConfig"
                    ]["Subnets"]
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


class Model(BaseModel):
    name: str
    region: str
    arn: str
    network_isolation: bool = None
    vpc_config_subnets: list[str] = []


class TrainingJob(BaseModel):
    name: str
    region: str
    arn: str
    container_traffic_encryption: bool = None
    volume_kms_key_id: str = None
    network_isolation: bool = None
    vpc_config_subnets: list[str] = []
