import io
import uuid
import random
import argparse
import concurrent.futures
import zipfile

from dataclasses import dataclass

import boto3


@dataclass
class RunningConfig:
    s3_buckets: int
    concurrency: int
    ec2_instances: int
    security_groups: int
    ecs_clusters: int
    cloudwatch_log_groups: int
    cloudwatch_log_streams: int
    lambda_functions: int
    ssm_parameters: int
    sagemaker_notebook_instances: int
    sagemaker_models: int
    sagemaker_training_jobs: int

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "RunningConfig":
        return cls(
            ec2_instances=args.ec2_instances,
            s3_buckets=args.s3_buckets,
            security_groups=args.security_groups,
            concurrency=args.concurrency,
            ecs_clusters=args.ecs_clusters,
            cloudwatch_log_groups=args.cloudwatch_log_groups,
            cloudwatch_log_streams=args.cloudwatch_log_streams,
            lambda_functions=args.lambda_functions,
            ssm_parameters=args.ssm_parameters,
            sagemaker_notebook_instances=args.sagemaker_notebook_instances,
            sagemaker_models=args.sagemaker_models,
            sagemaker_training_jobs=args.sagemaker_training_jobs,
        )


def create_security_groups(number: int = 5, concurrency: int = 10) -> list:
    ec2 = boto3.client("ec2")

    security_groups = [f"sg-{uuid.uuid4()}-{x}" for x in range(number)]

    print(f"[INFO] Creating {number} security groups")

    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for sg in security_groups:
            executor.submit(
                ec2.create_security_group,
                Description='test security group',
                GroupName=sg
            )

    print(f"[INFO] Created {number} security groups")

    return security_groups


def create_ec2_instances(number: int = 5, security_groups: list = None, concurrency: int = 5) -> None:
    ec2 = boto3.client("ec2")

    print(f"[INFO] Creating {number} EC2 instances")

    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for i in range(number):
            sg = random.choice(list(security_groups))

            executor.submit(
                ec2.run_instances,
                ImageId="ami-0c55b159cbfafe1f0",
                InstanceType="t2.micro",
                MinCount=1,
                MaxCount=1,
                KeyName=f"test-key-{uuid.uuid4()}-{i}",
                SecurityGroups=[sg]
            )

    print(f"[INFO] Created {number} EC2 instances")


def create_s3_buckets(number: int = 10, concurrency: int = 5) -> None:
    s3 = boto3.client("s3")

    print(f"[INFO] Creating {number} S3 buckets")

    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for i in range(number):
            executor.submit(s3.create_bucket, Bucket=f"{uuid.uuid4()}-{i}")

    print(f"[INFO] Created {number} S3 buckets")


def create_ecs_clusters(number: int = 10, concurrency: int = 5) -> None:
    ecs = boto3.client("ecs")

    print(f"[INFO] Creating {number} ECS clusters")

    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for i in range(number):
            executor.submit(ecs.create_cluster, clusterName=f"{uuid.uuid4()}-{i}")

    print(f"[INFO] Created {number} ECS clusters")


# Cloudwatch
def create_cloudwatch_log_groups(number_of_log_groups: int = 10, number_of_log_streams_per_log_group: int = 10,
                                 concurrency: int = 5) -> None:
    cw = boto3.client("logs")

    print(f"[INFO] Creating {number_of_log_groups} CloudWatch log groups")

    cloudwatch_log_groups = [
        f"{uuid.uuid4()}-{i}" for i in range(number_of_log_groups)
    ]
    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for name in cloudwatch_log_groups:
            executor.submit(cw.create_log_group, logGroupName=name)

    # add a log stream to each log group
    print(f"[INFO] Creating {number_of_log_streams_per_log_group} CloudWatch log streams")
    for log_group_name in cloudwatch_log_groups:
        log_streams = [
            f"{uuid.uuid4()}-{i}" for i in range(number_of_log_streams_per_log_group)
        ]
        with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
            for name in log_streams:
                executor.submit(
                    cw.create_log_stream,
                    logGroupName=log_group_name,
                    logStreamName=name,
                )

    print(f"[INFO] Created {number_of_log_groups} CloudWatch log groups and {number_of_log_streams_per_log_group} CloudWatch log streams")


def create_lambda_functions(number_of_lambda_functions: int = 10, concurrency: int = 5) -> None:
    def create_zip_file() -> bytes:
        """
        Create a zip file from the given code.

        Returns:
            io.BytesIO: The zip file.
        """
        python_code = """
def lambda_handler(event, context):
    print("Hello, World!")
"""

        zip_file = io.BytesIO()
        with zipfile.ZipFile(zip_file, "w") as zip:
            zip.writestr("lambda_function.py", python_code.encode("utf-8"))

        return zip_file.getvalue()

    lambda_client = boto3.client("lambda")

    print(f"[INFO] Creating {number_of_lambda_functions} Lambda functions")

    lambda_functions = [
        f"{uuid.uuid4()}-{i}" for i in range(number_of_lambda_functions)
    ]
    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for name in lambda_functions:
            executor.submit(
                lambda_client.create_function,
                FunctionName=name,
                Runtime="python3.11",
                Role="arn:aws:iam::000000000000:role/demo",
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": create_zip_file()},
                Description="test lambda function",
            )

    print(f"[INFO] Created {number_of_lambda_functions} Lambda functions")


def create_ssm(number_of_parameters: int = 10, concurrency: int = 5) -> None:
    ssm = boto3.client("ssm")

    print(f"[INFO] Creating {number_of_parameters} SSM parameters")
    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for i in range(number_of_parameters):
            executor.submit(
                ssm.put_parameter,
                Name=f"/test/parameter/{uuid.uuid4()}-{i}",
                Value=f"value{i}",
                Type="String",
                Overwrite=True,
            )

    print(f"[INFO] Created {number_of_parameters} SSM parameters")


def create_sagemaker(number_of_notebook_instances: int = 10, number_of_models: int = 10, number_of_training_jobs: int = 10,
                     concurrency: int = 5) -> None:
    sagemaker = boto3.client("sagemaker")

    print(f"[INFO] Creating {number_of_notebook_instances} SageMaker notebook instances")
    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for i in range(number_of_notebook_instances):
            executor.submit(
                sagemaker.create_notebook_instance,
                NotebookInstanceName=f"{uuid.uuid4()}-{i}",
                InstanceType="ml.t2.medium",
                RoleArn="arn:aws:iam::000000000000:role/demo",
                VolumeSizeInGB=10,
                DirectInternetAccess="Enabled",
            )

    print(f"[INFO] Created {number_of_notebook_instances} SageMaker notebook instances")

    print(f"[INFO] Creating {number_of_models} SageMaker models")
    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for i in range(number_of_models):
            executor.submit(
                sagemaker.create_model,
                ModelName=f"{uuid.uuid4()}-{i}",
                PrimaryContainer={
                    "Image": "abc123",
                    "ModelDataUrl": "s3://my-bucket/model.tar.gz",
                    "Environment": {
                        "SAGEMAKER_CONTAINER_LOG_LEVEL": "20",
                        "SAGEMAKER_REGION": "us-west-2",
                        "SAGEMAKER_SUBMIT_DIRECTORY": "/opt/ml/code",
                        "SAGEMAKER_PROGRAM": "train.py",
                        "SAGEMAKER_ENABLE_CLOUDWATCH_METRICS": "true",
                        "SAGEMAKER_JOB_NAME": "my-job",
                    },
                },
            )

    print(f"[INFO] Created {number_of_models} SageMaker models")

    print(f"[INFO] Creating {number_of_training_jobs} SageMaker training jobs")
    with concurrent.futures.ThreadPoolExecutor(concurrency) as executor:
        for i in range(number_of_training_jobs):
            executor.submit(
                sagemaker.create_training_job,
                TrainingJobName=f"{uuid.uuid4()}-{i}",
                RoleArn="arn:aws:iam::000000000000:role/demo",
                AlgorithmSpecification={
                    "TrainingImage": "abc123",
                    "TrainingInputMode": "File"
                },
                InputDataConfig=[
                    {
                        "ChannelName": "training",
                        "DataSource": {
                            "S3DataSource": {
                                "S3DataType": "S3Prefix",
                                "S3Uri": "s3://my-bucket/train",
                                "S3DataDistributionType": "FullyReplicated"
                            }
                        }
                    },
                    {
                        "ChannelName": "validation",
                        "DataSource": {
                            "S3DataSource": {
                                "S3DataType": "S3Prefix",
                                "S3Uri": "s3://my-bucket/validation",
                                "S3DataDistributionType": "FullyReplicated"
                            }
                        }
                    }
                ],
                OutputDataConfig={
                    "S3OutputPath": "s3://my-bucket/output"
                },
                ResourceConfig={
                    "InstanceCount": 1,
                    "InstanceType": "ml.t2.medium",
                    "VolumeSizeInGB": 10
                },
                StoppingCondition={
                    "MaxRuntimeInSeconds": 86400
                },
                VpcConfig={
                    "SecurityGroupIds": [
                        "sg-12345678"
                    ],
                    "Subnets": [
                        "subnet-12345678"
                    ]
                }
            )

    print(f"[INFO] Created {number_of_training_jobs} SageMaker training jobs")


def main(config: RunningConfig):
    concurrency = config.concurrency
    groups = create_security_groups(config.security_groups, concurrency)
    create_ec2_instances(config.ec2_instances, groups, concurrency)
    create_s3_buckets(config.s3_buckets, concurrency)
    create_ecs_clusters(config.ecs_clusters, concurrency)
    create_cloudwatch_log_groups(config.cloudwatch_log_groups, concurrency)
    create_lambda_functions(config.lambda_functions, concurrency)
    create_ssm(config.ssm_parameters, concurrency)
    create_sagemaker(config.sagemaker_notebook_instances, config.sagemaker_models, config.sagemaker_training_jobs, concurrency)


if __name__ == '__main__':
    cli = argparse.ArgumentParser(prog="populate", description="Populate AWS resources")

    # Add concurrency
    cli.add_argument(
        "-c", "--concurrency", type=int, help="Number of concurrent threads to use", default=20
    )

    cli.add_argument(
        "-e", "--ec2-instances", type=int, help="Number of EC2 instances to create", default=5
    )
    cli.add_argument(
        "-s", "--s3-buckets", type=int, help="Number of S3 buckets to create", default=5
    )
    cli.add_argument(
        "-g", "--security-groups", type=int, help="Number of security groups to create", default=5
    )
    cli.add_argument(
        "-r", "--ecs-clusters", type=int, help="Number of ECS clusters to create", default=5
    )
    cli.add_argument(
        "-l", "--cloudwatch-log-groups", type=int, help="Number of CloudWatch log groups to create", default=5
    )
    cli.add_argument(
        "-m", "--cloudwatch-log-streams", type=int, help="Number of CloudWatch log streams to create", default=10
    )
    # lambda
    cli.add_argument(
        "-f", "--lambda-functions", type=int, help="Number of Lambda functions to create", default=5
    )
    # ssm
    cli.add_argument(
        "-p", "--ssm-parameters", type=int, help="Number of SSM parameters to create", default=5
    )
    # sagemaker
    cli.add_argument(
        "-n", "--sagemaker-notebook-instances", type=int, help="Number of SageMaker notebook instances to create", default=5
    )
    cli.add_argument(
        "-M", "--sagemaker-models", type=int, help="Number of SageMaker models to create", default=5
    )
    cli.add_argument(
        "-t", "--sagemaker-training-jobs", type=int, help="Number of SageMaker training jobs to create", default=5
    )

    args = cli.parse_args()

    main(RunningConfig.from_args(args))
