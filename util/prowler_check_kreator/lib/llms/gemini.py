import json
import os

import google.generativeai as genai

from util.prowler_check_kreator.lib.metadata_types import (
    get_metadata_placeholder_resource_type,
    get_metadata_valid_check_type,
    get_metadata_valid_resource_type,
)


class Gemini:
    def __init__(self, model: str = "gemini-1.5-flash"):
        if os.getenv("GEMINI_API_KEY"):
            self.api_key = os.getenv("GEMINI_API_KEY")
        else:
            self.api_key = input(
                "GEMINI_API_KEY is not set, please enter the API key: "
            )
            if not self.api_key:
                raise Exception("GEMINI_API_KEY is required")

        if model not in ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"]:
            raise Exception("Invalid Gemini AI model")

        self.model_name = model
        self.generation_config = {
            "temperature": 0,
            "top_p": 1,
            "top_k": 1,
        }
        self.safety_settings = [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
        ]
        self._configure_genai()

    def _configure_genai(self):
        """Configure the Gemini AI model."""
        try:
            genai.configure(api_key=self.api_key)
        except Exception as e:
            raise Exception(f"Error configuring Gemini AI: {e}")

    def _generate_content(self, prompt_parts: list) -> str:
        """Generate content using Gemini AI based on provided prompts."""
        try:
            model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config=self.generation_config,
                safety_settings=self.safety_settings,
            )
            response = model.generate_content(prompt_parts)
            if response:
                return response.text
            else:
                raise Exception("Error generating content with Gemini AI")
        except Exception as e:
            raise Exception(f"Error generating content with Gemini AI: {e}")

    def _prepare_check_prompt(self, check_name: str, context: str) -> list:
        """Prepare the prompt for generating the check."""

        prompt_parts = [
            "You are a AWS cybersecurity engineer working in Prowler, an open-source Cloud Security tool to audit Cloud environments in an automated way.",
            f"Your task is to create a new security check called '{check_name}' based on the following context:\n{context}",
            "TA check is a Python class that inherits from the Check class and has only one method called execute.\n",
            "The execute method must return a list of Check_Report_AWS objects.\n",
            "Limit to Python code only.\n",
            "Use the following check as inspiration about the format to create the new check:\n",
            "ec2_instance_port_ssh_exposed_to_internet:",
            "from prowler.lib.check.models import Check, Check_Report_AWS\nfrom prowler.providers.aws.services.ec2.ec2_client import ec2_client\nfrom prowler.providers.aws.services.ec2.lib.instance import get_instance_public_status\nfrom prowler.providers.aws.services.ec2.lib.security_groups import check_security_group\nfrom prowler.providers.aws.services.vpc.vpc_client import vpc_client\n\n\nclass ec2_instance_port_ssh_exposed_to_internet(Check):\n\t# EC2 Instances with SSH port 22 open to the Internet will be flagged as FAIL with a severity of medium if the instance has no public IP, high if the instance has a public IP but is in a private subnet, and critical if the instance has a public IP and is in a public subnet.\n\tdef execute(self):\n\t\tfindings = []\n\t\tcheck_ports = [22]\n\t\tfor instance in ec2_client.instances:\n\t\t\treport = Check_Report_AWS(self.metadata())\n\t\t\treport.region = instance.region\n\t\t\treport.status = 'PASS'\n\t\t\treport.status_extended = f'Instance {instance.id} does not have SSH port 22 open to the Internet.'\n\t\t\treport.resource_id = instance.id\n\t\t\treport.resource_arn = instance.arn\n\t\t\treport.resource_tags = instance.tags\n\t\t\tis_open_port = False\n\t\t\tif instance.security_groups:\n\t\t\t\tfor sg in ec2_client.security_groups.values():\n\t\t\t\t\tif sg.id in instance.security_groups:\n\t\t\t\t\t\tfor ingress_rule in sg.ingress_rules:\n\t\t\t\t\t\t\tif check_security_group(\n\t\t\t\t\t\t\t\tingress_rule, 'tcp', check_ports, any_address=True\n\t\t\t\t\t\t\t):\n\t\t\t\t\t\t\t\t# The port is open, now check if the instance is in a public subnet with a public IP\n\t\t\t\t\t\t\t\treport.status = 'FAIL'\n\t\t\t\t\t\t\t\t(\n\t\t\t\t\t\t\t\t\treport.status_extended,\n\t\t\t\t\t\t\t\t\treport.check_metadata.Severity,\n\t\t\t\t\t\t\t\t) = get_instance_public_status(\n\t\t\t\t\t\t\t\t\tvpc_client.vpc_subnets, instance, 'SSH'\n\t\t\t\t\t\t\t\t)\n\t\t\t\t\t\t\t\tis_open_port = True\n\t\t\t\t\t\t\t\tbreak\n\t\t\t\t\t\tif is_open_port:\n\t\t\t\t\t\t\tbreak\n\t\t\tfindings.append(report)\n\t\treturn findings\n",
            "s3_bucket_default_encryption:",
            "from prowler.lib.check.models import Check, Check_Report_AWS\nfrom prowler.providers.aws.services.s3.s3_client import s3_client\n\n\nclass s3_bucket_default_encryption(Check):\n\tdef execute(self):\n\t\tfindings = []\n\t\tfor arn, bucket in s3_client.buckets.items():\n\t\t\treport = Check_Report_AWS(self.metadata())\n\t\t\treport.region = bucket.region\n\t\t\treport.resource_id = bucket.name\n\t\t\treport.resource_arn = arn\n\t\t\treport.resource_tags = bucket.tags\n\t\t\tif bucket.encryption:\n\t\t\t\treport.status = 'PASS'\n\t\t\t\treport.status_extended = f'S3 Bucket {bucket.name} has Server Side Encryption with {bucket.encryption}.'\n\t\t\telse:\n\t\t\t\treport.status = 'FAIL'\n\t\t\t\treport.status_extended = f'S3 Bucket {bucket.name} does not have Server Side Encryption enabled.'\n\t\t\tfindings.append(report)\n\t\treturn findings\n",
            "bedrock_guardrail_prompt_attack_filter_enabled:",
            "from prowler.lib.check.models import Check, Check_Report_AWS\nfrom prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client\n\n\nclass bedrock_guardrail_prompt_attack_filter_enabled(Check):\n\tdef execute(self):\n\t\tfindings = []\n\t\tfor guardrail in bedrock_client.guardrails.values():\n\t\t\treport = Check_Report_AWS(self.metadata())\n\t\t\treport.region = guardrail.region\n\t\t\treport.resource_id = guardrail.id\n\t\t\treport.resource_arn = guardrail.arn\n\t\t\treport.resource_tags = guardrail.tags\n\t\t\treport.status = 'PASS'\n\t\t\treport.status_extended = f'Bedrock Guardrail {guardrail.name} is configured to detect and block prompt attacks with a HIGH strength.'\n\t\t\tif not guardrail.prompt_attack_filter_strength:\n\t\t\t\treport.status = 'FAIL'\n\t\t\t\treport.status_extended = f'Bedrock Guardrail {guardrail.name} is not configured to block prompt attacks.'\n\t\t\telif guardrail.prompt_attack_filter_strength != 'HIGH':\n\t\t\t\treport.status = 'FAIL'\n\t\t\t\treport.status_extended = f'Bedrock Guardrail {guardrail.name} is configured to block prompt attacks but with a filter strength of {guardrail.prompt_attack_filter_strength}, not HIGH.'\n\t\t\tfindings.append(report)\n\n\t\treturn findings",
            "cloudwatch_alarm_actions_enabled:",
            "from prowler.lib.check.models import Check, Check_Report_AWS\nfrom prowler.providers.aws.services.cloudwatch.cloudwatch_client import (\n\tcloudwatch_client,\n)\n\n\nclass cloudwatch_alarm_actions_enabled(Check):\n\tdef execute(self):\n\t\tfindings = []\n\t\tfor metric_alarm in cloudwatch_client.metric_alarms:\n\t\t\treport = Check_Report_AWS(self.metadata())\n\t\t\treport.region = metric_alarm.region\n\t\t\treport.resource_id = metric_alarm.name\n\t\t\treport.resource_arn = metric_alarm.arn\n\t\t\treport.resource_tags = metric_alarm.tags\n\t\t\treport.status = 'PASS'\n\t\t\treport.status_extended = (\n\t\t\t\tf'CloudWatch metric alarm {metric_alarm.name} has actions enabled.'\n\t\t\t)\n\t\t\tif not metric_alarm.actions_enabled:\n\t\t\t\treport.status = 'FAIL'\n\t\t\t\treport.status_extended = f'CloudWatch metric alarm {metric_alarm.name} does not have actions enabled.'\n\t\t\tfindings.append(report)\n\t\treturn findings",
            "awslambda_function_not_publicly_accessible:",
            "from prowler.lib.check.models import Check, Check_Report_AWS\nfrom prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client\nfrom prowler.providers.aws.services.iam.lib.policy import is_policy_public\n\n\nclass awslambda_function_not_publicly_accessible(Check):\n\tdef execute(self):\n\t\tfindings = []\n\t\tfor function in awslambda_client.functions.values():\n\t\t\treport = Check_Report_AWS(self.metadata())\n\t\t\treport.region = function.region\n\t\t\treport.resource_id = function.name\n\t\t\treport.resource_arn = function.arn\n\t\t\treport.resource_tags = function.tags\n\n\t\t\treport.status = 'PASS'\n\t\t\treport.status_extended = f'Lambda function {function.name} has a policy resource-based policy not public.'\n\t\t\tif is_policy_public(\n\t\t\t\tfunction.policy,\n\t\t\t\tawslambda_client.audited_account,\n\t\t\t\tis_cross_account_allowed=True,\n\t\t\t):\n\t\t\t\treport.status = 'FAIL'\n\t\t\t\treport.status_extended = f'Lambda function {function.name} has a policy resource-based policy with public access.'\n\n\t\t\tfindings.append(report)\n\n\t\treturn findings",
            f"{check_name}:",
        ]
        return prompt_parts

    def _prepare_test_prompt(self, check_name: str) -> list:
        """Prepare the prompt for generating the test."""

        prompt_parts = [
            "You are a AWS cybersecurity engineer working in Prowler, an open-source Cloud Security tool to audit Cloud environments in an automated way.",
            f"Your task is to create a new unit test for the security check '{check_name}'.",
            "The test must have one or more methods that start with the word 'test'.",
            "The test methods must use the assert statement to check the results of the check.",
            "I need the answer only with Python formatted text.",
            "Use the following test as inspiration to create the new test: ",
            "ec2_instance_port_ssh_exposed_to_internet:",
            "from unittest import mock\n\nfrom boto3 import client, resource\nfrom moto import mock_aws\n\nfrom tests.providers.aws.utils import (\n\tAWS_REGION_EU_WEST_1,\n\tAWS_REGION_US_EAST_1,\n\tset_mocked_aws_provider,\n)\n\n\nclass Test_ec2_instance_port_ssh_exposed_to_internet:\n\t@mock_aws\n\tdef test_no_ec2_instances(self):\n\t\t# Create EC2 Mocked Resources\n\t\tec2_client = client('ec2', region_name=AWS_REGION_US_EAST_1)\n\t\tec2_client.create_vpc(CidrBlock='10.0.0.0/16')\n\n\t\tfrom prowler.providers.aws.services.ec2.ec2_service import EC2\n\t\tfrom prowler.providers.aws.services.vpc.vpc_service import VPC\n\n\t\taws_provider = set_mocked_aws_provider(\n\t\t\t[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]\n\t\t)\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet.ec2_client',\n\t\t\tnew=EC2(aws_provider),\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet.vpc_client',\n\t\t\tnew=VPC(aws_provider),\n\t\t):\n\t\t\t# Test Check\n\t\t\tfrom prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet import (\n\t\t\t\tec2_instance_port_ssh_exposed_to_internet,\n\t\t\t)\n\n\t\t\tcheck = ec2_instance_port_ssh_exposed_to_internet()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 0\n\n\t@mock_aws\n\tdef test_ec2_instance_no_port_exposed(self):\n\t\t# Create EC2 Mocked Resources\n\t\tec2_client = client('ec2', region_name=AWS_REGION_US_EAST_1)\n\t\tec2_resource = resource('ec2', region_name=AWS_REGION_US_EAST_1)\n\t\tvpc_id = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']\n\t\tdefault_sg = ec2_client.describe_security_groups(GroupNames=['default'])[\n\t\t\t'SecurityGroups'\n\t\t][0]\n\t\tdefault_sg_id = default_sg['GroupId']\n\t\tec2_client.authorize_security_group_ingress(\n\t\t\tGroupId=default_sg_id,\n\t\t\tIpPermissions=[\n\t\t\t\t{\n\t\t\t\t\t'IpProtocol': 'tcp',\n\t\t\t\t\t'FromPort': 22,\n\t\t\t\t\t'ToPort': 22,\n\t\t\t\t\t'IpRanges': [{'CidrIp': '123.123.123.123/32'}],\n\t\t\t\t}\n\t\t\t],\n\t\t)\n\t\tsubnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock='10.0.0.0/16')[\n\t\t\t'Subnet'\n\t\t]['SubnetId']\n\t\tinstance_id = ec2_resource.create_instances(\n\t\t\tImageId='ami-12345678',\n\t\t\tMinCount=1,\n\t\t\tMaxCount=1,\n\t\t\tInstanceType='t2.micro',\n\t\t\tSecurityGroupIds=[default_sg_id],\n\t\t\tSubnetId=subnet_id,\n\t\t\tTagSpecifications=[\n\t\t\t\t{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': 'test'}]}\n\t\t\t],\n\t\t)[0].id\n\n\t\tfrom prowler.providers.aws.services.ec2.ec2_service import EC2\n\t\tfrom prowler.providers.aws.services.vpc.vpc_service import VPC\n\n\t\taws_provider = set_mocked_aws_provider(\n\t\t\t[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]\n\t\t)\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet.ec2_client',\n\t\t\tnew=EC2(aws_provider),\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet.vpc_client',\n\t\t\tnew=VPC(aws_provider),\n\t\t):\n\t\t\t# Test Check\n\t\t\tfrom prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet import (\n\t\t\t\tec2_instance_port_ssh_exposed_to_internet,\n\t\t\t)\n\n\t\t\tcheck = ec2_instance_port_ssh_exposed_to_internet()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 1\n\t\t\tassert result[0].status == 'PASS'\n\t\t\tassert (\n\t\t\t\tresult[0].status_extended\n\t\t\t\t== f'Instance {instance_id} does not have SSH port 22 open to the Internet.'\n\t\t\t)\n\t\t\tassert result[0].resource_id == instance_id\n\t\t\tassert (\n\t\t\t\tresult[0].resource_arn\n\t\t\t\t== f'arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance_id}'\n\t\t\t)\n\t\t\tassert result[0].resource_tags == [{'Key': 'Name', 'Value': 'test'}]\n\t\t\tassert result[0].region == AWS_REGION_US_EAST_1\n\t\t\tassert result[0].check_metadata.Severity == 'critical'\n\n\t@mock_aws\n\tdef test_ec2_instance_exposed_port_in_private_subnet(self):\n\t\t# Create EC2 Mocked Resources\n\t\tec2_client = client('ec2', region_name=AWS_REGION_US_EAST_1)\n\t\tec2_resource = resource('ec2', region_name=AWS_REGION_US_EAST_1)\n\t\tvpc_id = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']\n\t\tdefault_sg = ec2_client.describe_security_groups(GroupNames=['default'])[\n\t\t\t'SecurityGroups'\n\t\t][0]\n\t\tdefault_sg_id = default_sg['GroupId']\n\t\tec2_client.authorize_security_group_ingress(\n\t\t\tGroupId=default_sg_id,\n\t\t\tIpPermissions=[\n\t\t\t\t{\n\t\t\t\t\t'IpProtocol': 'tcp',\n\t\t\t\t\t'FromPort': 22,\n\t\t\t\t\t'ToPort': 22,\n\t\t\t\t\t'IpRanges': [{'CidrIp': '0.0.0.0/0'}],\n\t\t\t\t}\n\t\t\t],\n\t\t)\n\t\tsubnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock='10.0.0.0/16')[\n\t\t\t'Subnet'\n\t\t]['SubnetId']\n\t\tinstance_id = ec2_resource.create_instances(\n\t\t\tImageId='ami-12345678',\n\t\t\tMinCount=1,\n\t\t\tMaxCount=1,\n\t\t\tInstanceType='t2.micro',\n\t\t\tSecurityGroupIds=[default_sg_id],\n\t\t\tSubnetId=subnet_id,\n\t\t\tTagSpecifications=[\n\t\t\t\t{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': 'test'}]}\n\t\t\t],\n\t\t)[0].id\n\n\t\tfrom prowler.providers.aws.services.ec2.ec2_service import EC2\n\t\tfrom prowler.providers.aws.services.vpc.vpc_service import VPC\n\n\t\taws_provider = set_mocked_aws_provider(\n\t\t\t[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]\n\t\t)\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet.ec2_client',\n\t\t\tnew=EC2(aws_provider),\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet.vpc_client',\n\t\t\tnew=VPC(aws_provider),\n\t\t):\n\t\t\t# Test Check\n\t\t\tfrom prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet import (\n\t\t\t\tec2_instance_port_ssh_exposed_to_internet,\n\t\t\t)\n\n\t\t\tcheck = ec2_instance_port_ssh_exposed_to_internet()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 1\n\t\t\tassert result[0].status == 'FAIL'\n\t\t\tassert (\n\t\t\t\tresult[0].status_extended\n\t\t\t\t== f'Instance {instance_id} has SSH exposed to 0.0.0.0/0 but with no public IP address.'\n\t\t\t)\n\t\t\tassert result[0].resource_id == instance_id\n\t\t\tassert (\n\t\t\t\tresult[0].resource_arn\n\t\t\t\t== f'arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance_id}'\n\t\t\t)\n\t\t\tassert result[0].resource_tags == [{'Key': 'Name', 'Value': 'test'}]\n\t\t\tassert result[0].region == AWS_REGION_US_EAST_1\n\t\t\tassert result[0].check_metadata.Severity == 'medium'",
            "s3_bucket_default_encryption:",
            "from unittest import mock\n\nfrom boto3 import client\nfrom moto import mock_aws\n\nfrom tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider\n\n\nclass Test_s3_bucket_default_encryption:\n\t@mock_aws\n\tdef test_bucket_no_encryption(self):\n\t\ts3_client_us_east_1 = client('s3', region_name=AWS_REGION_US_EAST_1)\n\t\tbucket_name_us = 'bucket_test_us'\n\t\ts3_client_us_east_1.create_bucket(Bucket=bucket_name_us)\n\n\t\tfrom prowler.providers.aws.services.s3.s3_service import S3\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t):\n\t\t\twith mock.patch(\n\t\t\t\t'prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption.s3_client',\n\t\t\t\tnew=S3(aws_provider),\n\t\t\t):\n\t\t\t\t# Test Check\n\t\t\t\tfrom prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption import (\n\t\t\t\t\ts3_bucket_default_encryption,\n\t\t\t\t)\n\n\t\t\t\tcheck = s3_bucket_default_encryption()\n\t\t\t\tresult = check.execute()\n\n\t\t\t\tassert len(result) == 1\n\t\t\t\tassert result[0].status == 'FAIL'\n\t\t\t\tassert (\n\t\t\t\t\tresult[0].status_extended\n\t\t\t\t\t== f'S3 Bucket {bucket_name_us} does not have Server Side Encryption enabled.'\n\t\t\t\t)\n\t\t\t\tassert result[0].resource_id == bucket_name_us\n\t\t\t\tassert (\n\t\t\t\t\tresult[0].resource_arn\n\t\t\t\t\t== f'arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}'\n\t\t\t\t)\n\t\t\t\tassert result[0].region == AWS_REGION_US_EAST_1\n\n\t@mock_aws\n\tdef test_bucket_kms_encryption(self):\n\t\ts3_client_us_east_1 = client('s3', region_name=AWS_REGION_US_EAST_1)\n\t\tbucket_name_us = 'bucket_test_us'\n\t\ts3_client_us_east_1.create_bucket(\n\t\t\tBucket=bucket_name_us, ObjectOwnership='BucketOwnerEnforced'\n\t\t)\n\t\tsse_config = {\n\t\t\t'Rules': [\n\t\t\t\t{\n\t\t\t\t\t'ApplyServerSideEncryptionByDefault': {\n\t\t\t\t\t\t'SSEAlgorithm': 'aws:kms',\n\t\t\t\t\t\t'KMSMasterKeyID': '12345678',\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t]\n\t\t}\n\n\t\ts3_client_us_east_1.put_bucket_encryption(\n\t\t\tBucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config\n\t\t)\n\n\t\tfrom prowler.providers.aws.services.s3.s3_service import S3\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t):\n\t\t\twith mock.patch(\n\t\t\t\t'prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption.s3_client',\n\t\t\t\tnew=S3(aws_provider),\n\t\t\t):\n\t\t\t\t# Test Check\n\t\t\t\tfrom prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption import (\n\t\t\t\t\ts3_bucket_default_encryption,\n\t\t\t\t)\n\n\t\t\t\tcheck = s3_bucket_default_encryption()\n\t\t\t\tresult = check.execute()\n\n\t\t\t\tassert len(result) == 1\n\t\t\t\tassert result[0].status == 'PASS'\n\t\t\t\tassert (\n\t\t\t\t\tresult[0].status_extended\n\t\t\t\t\t== f'S3 Bucket {bucket_name_us} has Server Side Encryption with aws:kms.'\n\t\t\t\t)\n\t\t\t\tassert result[0].resource_id == bucket_name_us\n\t\t\t\tassert (\n\t\t\t\t\tresult[0].resource_arn\n\t\t\t\t\t== f'arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}'\n\t\t\t\t)\n\t\t\t\tassert result[0].region == AWS_REGION_US_EAST_1",
            "cloudwatch_alarm_actions_enabled:",
            "from unittest import mock\n\nfrom boto3 import client\nfrom moto import mock_aws\n\nfrom tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider\n\n\nclass Test_cloudwatch_alarm_actions_enabled:\n\t@mock_aws\n\tdef test_no_cloudwatch_alarms(self):\n\t\tcloudwatch_client = client('cloudwatch', region_name=AWS_REGION_US_EAST_1)\n\t\tcloudwatch_client.metric_alarms = []\n\n\t\tfrom prowler.providers.aws.services.cloudwatch.cloudwatch_service import (\n\t\t\tCloudWatch,\n\t\t)\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled.cloudwatch_client',\n\t\t\tnew=CloudWatch(aws_provider),\n\t\t):\n\n\t\t\tfrom prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled import (\n\t\t\t\tcloudwatch_alarm_actions_enabled,\n\t\t\t)\n\n\t\t\tcheck = cloudwatch_alarm_actions_enabled()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 0\n\n\t@mock_aws\n\tdef test_cloudwatch_alarms_actions_enabled(self):\n\t\tcloudwatch_client = client('cloudwatch', region_name=AWS_REGION_US_EAST_1)\n\t\tcloudwatch_client.put_metric_alarm(\n\t\t\tAlarmName='test_alarm',\n\t\t\tAlarmDescription='Test alarm',\n\t\t\tActionsEnabled=True,\n\t\t\tAlarmActions=['arn:aws:sns:us-east-1:123456789012:my-sns-topic'],\n\t\t\tEvaluationPeriods=1,\n\t\t\tComparisonOperator='GreaterThanThreshold',\n\t\t)\n\n\t\tfrom prowler.providers.aws.services.cloudwatch.cloudwatch_service import (\n\t\t\tCloudWatch,\n\t\t)\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled.cloudwatch_client',\n\t\t\tnew=CloudWatch(aws_provider),\n\t\t):\n\n\t\t\tfrom prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled import (\n\t\t\t\tcloudwatch_alarm_actions_enabled,\n\t\t\t)\n\n\t\t\tcheck = cloudwatch_alarm_actions_enabled()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 1\n\t\t\tassert result[0].status == 'PASS'\n\t\t\tassert (\n\t\t\t\tresult[0].status_extended\n\t\t\t\t== 'CloudWatch metric alarm test_alarm has actions enabled.'\n\t\t\t)\n\t\t\tassert result[0].resource_id == 'test_alarm'\n\t\t\tassert (\n\t\t\t\tresult[0].resource_arn\n\t\t\t\t== 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:test_alarm'\n\t\t\t)\n\t\t\tassert result[0].region == AWS_REGION_US_EAST_1\n\t\t\tassert result[0].resource_tags == []\n\n\t@mock_aws\n\tdef test_cloudwatch_alarms_actions_disabled(self):\n\t\tcloudwatch_client = client('cloudwatch', region_name=AWS_REGION_US_EAST_1)\n\t\tcloudwatch_client.put_metric_alarm(\n\t\t\tAlarmName='test_alarm',\n\t\t\tAlarmDescription='Test alarm',\n\t\t\tActionsEnabled=False,\n\t\t\tAlarmActions=['arn:aws:sns:us-east-1:123456789012:my-sns-topic'],\n\t\t\tEvaluationPeriods=1,\n\t\t\tComparisonOperator='GreaterThanThreshold',\n\t\t)\n\n\t\tfrom prowler.providers.aws.services.cloudwatch.cloudwatch_service import (\n\t\t\tCloudWatch,\n\t\t)\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled.cloudwatch_client',\n\t\t\tnew=CloudWatch(aws_provider),\n\t\t):\n\n\t\t\tfrom prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled import (\n\t\t\t\tcloudwatch_alarm_actions_enabled,\n\t\t\t)\n\n\t\t\tcheck = cloudwatch_alarm_actions_enabled()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 1\n\t\t\tassert result[0].status == 'FAIL'\n\t\t\tassert (\n\t\t\t\tresult[0].status_extended\n\t\t\t\t== 'CloudWatch metric alarm test_alarm does not have actions enabled.'\n\t\t\t)\n\t\t\tassert result[0].resource_id == 'test_alarm'\n\t\t\tassert (\n\t\t\t\tresult[0].resource_arn\n\t\t\t\t== 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:test_alarm'\n\t\t\t)\n\t\t\tassert result[0].region == AWS_REGION_US_EAST_1\n\t\t\tassert result[0].resource_tags == []",
            "awslambda_function_not_publicly_accessible:",
            "from json import dumps\nfrom unittest import mock\n\nfrom boto3 import client\nfrom moto import mock_aws\n\nfrom prowler.providers.aws.services.awslambda.awslambda_service import Function\nfrom tests.providers.aws.utils import (\n\tAWS_ACCOUNT_NUMBER,\n\tAWS_REGION_EU_WEST_1,\n\tset_mocked_aws_provider,\n)\n\n\nclass Test_awslambda_function_not_publicly_accessible:\n\t@mock_aws\n\tdef test_no_functions(self):\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])\n\n\t\tfrom prowler.providers.aws.services.awslambda.awslambda_service import Lambda\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client',\n\t\t\tnew=Lambda(aws_provider),\n\t\t):\n\t\t\t# Test Check\n\t\t\tfrom prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (\n\t\t\t\tawslambda_function_not_publicly_accessible,\n\t\t\t)\n\n\t\t\tcheck = awslambda_function_not_publicly_accessible()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 0\n\n\t@mock_aws\n\tdef test_function_public(self):\n\t\t# Create the mock IAM role\n\t\tiam_client = client('iam', region_name=AWS_REGION_EU_WEST_1)\n\t\trole_name = 'test-role'\n\t\tassume_role_policy_document = {\n\t\t\t'Version': '2012-10-17',\n\t\t\t'Statement': [\n\t\t\t\t{\n\t\t\t\t\t'Effect': 'Allow',\n\t\t\t\t\t'Principal': {'Service': 'lambda.amazonaws.com'},\n\t\t\t\t\t'Action': 'sts:AssumeRole',\n\t\t\t\t}\n\t\t\t],\n\t\t}\n\t\trole_arn = iam_client.create_role(\n\t\t\tRoleName=role_name,\n\t\t\tAssumeRolePolicyDocument=dumps(assume_role_policy_document),\n\t\t)['Role']['Arn']\n\n\t\tfunction_name = 'test-lambda'\n\n\t\t# Create the lambda function using boto3 client\n\t\tlambda_client = client('lambda', region_name=AWS_REGION_EU_WEST_1)\n\t\tfunction_arn = lambda_client.create_function(\n\t\t\tFunctionName=function_name,\n\t\t\tRuntime='nodejs4.3',\n\t\t\tRole=role_arn,\n\t\t\tHandler='index.handler',\n\t\t\tCode={'ZipFile': b'fileb://file-path/to/your-deployment-package.zip'},\n\t\t\tDescription='Test Lambda function',\n\t\t\tTimeout=3,\n\t\t\tMemorySize=128,\n\t\t\tPublish=True,\n\t\t\tTags={'tag1': 'value1', 'tag2': 'value2'},\n\t\t)['FunctionArn']\n\n\t\t# Attach the policy to the lambda function with a wildcard principal\n\t\tlambda_client.add_permission(\n\t\t\tFunctionName=function_name,\n\t\t\tStatementId='public-access',\n\t\t\tAction='lambda:InvokeFunction',\n\t\t\tPrincipal='*',\n\t\t)\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])\n\n\t\tfrom prowler.providers.aws.services.awslambda.awslambda_service import Lambda\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client',\n\t\t\tnew=Lambda(aws_provider),\n\t\t):\n\t\t\t# Test Check\n\t\t\tfrom prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (\n\t\t\t\tawslambda_function_not_publicly_accessible,\n\t\t\t)\n\n\t\t\tcheck = awslambda_function_not_publicly_accessible()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 1\n\t\t\tassert result[0].region == AWS_REGION_EU_WEST_1\n\t\t\tassert result[0].resource_id == function_name\n\t\t\tassert result[0].resource_arn == function_arn\n\t\t\tassert result[0].status == 'FAIL'\n\t\t\tassert (\n\t\t\t\tresult[0].status_extended\n\t\t\t\t== f'Lambda function {function_name} has a policy resource-based policy with public access.'\n\t\t\t)\n\t\t\tassert result[0].resource_tags == [{'tag1': 'value1', 'tag2': 'value2'}]\n\n\t@mock_aws\n\tdef test_function_public_with_source_account(self):\n\t\t# Create the mock IAM role\n\t\tiam_client = client('iam', region_name=AWS_REGION_EU_WEST_1)\n\t\trole_name = 'test-role'\n\t\tassume_role_policy_document = {\n\t\t\t'Version': '2012-10-17',\n\t\t\t'Statement': [\n\t\t\t\t{\n\t\t\t\t\t'Effect': 'Allow',\n\t\t\t\t\t'Principal': {'Service': 'lambda.amazonaws.com'},\n\t\t\t\t\t'Action': 'sts:AssumeRole',\n\t\t\t\t}\n\t\t\t],\n\t\t}\n\t\trole_arn = iam_client.create_role(\n\t\t\tRoleName=role_name,\n\t\t\tAssumeRolePolicyDocument=dumps(assume_role_policy_document),\n\t\t)['Role']['Arn']\n\n\t\tfunction_name = 'test-lambda'\n\n\t\t# Create the lambda function using boto3 client\n\t\tlambda_client = client('lambda', region_name=AWS_REGION_EU_WEST_1)\n\t\tfunction_arn = lambda_client.create_function(\n\t\t\tFunctionName=function_name,\n\t\t\tRuntime='nodejs4.3',\n\t\t\tRole=role_arn,\n\t\t\tHandler='index.handler',\n\t\t\tCode={'ZipFile': b'fileb://file-path/to/your-deployment-package.zip'},\n\t\t\tDescription='Test Lambda function',\n\t\t\tTimeout=3,\n\t\t\tMemorySize=128,\n\t\t\tPublish=True,\n\t\t\tTags={'tag1': 'value1', 'tag2': 'value2'},\n\t\t)['FunctionArn']\n\n\t\t# Attach the policy to the lambda function with a wildcard principal\n\t\tlambda_client.add_permission(\n\t\t\tFunctionName=function_name,\n\t\t\tStatementId='non-public-access',\n\t\t\tAction='lambda:InvokeFunction',\n\t\t\tPrincipal='*',\n\t\t\tSourceArn=function_arn,\n\t\t\tSourceAccount=AWS_ACCOUNT_NUMBER,\n\t\t)\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])\n\n\t\tfrom prowler.providers.aws.services.awslambda.awslambda_service import Lambda\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client',\n\t\t\tnew=Lambda(aws_provider),\n\t\t):\n\t\t\t# Test Check\n\t\t\tfrom prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (\n\t\t\t\tawslambda_function_not_publicly_accessible,\n\t\t\t)\n\n\t\t\tcheck = awslambda_function_not_publicly_accessible()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 1\n\t\t\tassert result[0].region == AWS_REGION_EU_WEST_1\n\t\t\tassert result[0].resource_id == function_name\n\t\t\tassert result[0].resource_arn == function_arn\n\t\t\tassert result[0].status == 'PASS'\n\t\t\tassert (\n\t\t\t\tresult[0].status_extended\n\t\t\t\t== f'Lambda function {function_name} has a policy resource-based policy not public.'\n\t\t\t)\n\t\t\tassert result[0].resource_tags == [{'tag1': 'value1', 'tag2': 'value2'}]\n\n\t@mock_aws\n\tdef test_function_not_public(self):\n\t\t# Create the mock IAM role\n\t\tiam_client = client('iam', region_name=AWS_REGION_EU_WEST_1)\n\t\trole_name = 'test-role'\n\t\tassume_role_policy_document = {\n\t\t\t'Version': '2012-10-17',\n\t\t\t'Statement': [\n\t\t\t\t{\n\t\t\t\t\t'Effect': 'Allow',\n\t\t\t\t\t'Principal': {'Service': 'lambda.amazonaws.com'},\n\t\t\t\t\t'Action': 'sts:AssumeRole',\n\t\t\t\t}\n\t\t\t],\n\t\t}\n\t\trole_arn = iam_client.create_role(\n\t\t\tRoleName=role_name,\n\t\t\tAssumeRolePolicyDocument=dumps(assume_role_policy_document),\n\t\t)['Role']['Arn']\n\n\t\tfunction_name = 'test-lambda'\n\n\t\t# Create the lambda function using boto3 client\n\t\tlambda_client = client('lambda', region_name=AWS_REGION_EU_WEST_1)\n\t\tfunction_arn = lambda_client.create_function(\n\t\t\tFunctionName=function_name,\n\t\t\tRuntime='nodejs4.3',\n\t\t\tRole=role_arn,\n\t\t\tHandler='index.handler',\n\t\t\tCode={'ZipFile': b'fileb://file-path/to/your-deployment-package.zip'},\n\t\t\tDescription='Test Lambda function',\n\t\t\tTimeout=3,\n\t\t\tMemorySize=128,\n\t\t\tPublish=True,\n\t\t\tTags={'tag1': 'value1', 'tag2': 'value2'},\n\t\t)['FunctionArn']\n\n\t\t# Attach the policy to the lambda function with a specific AWS account number as principal\n\t\tlambda_client.add_permission(\n\t\t\tFunctionName=function_name,\n\t\t\tStatementId='public-access',\n\t\t\tAction='lambda:InvokeFunction',\n\t\t\tPrincipal=AWS_ACCOUNT_NUMBER,\n\t\t\tSourceArn=function_arn,\n\t\t)\n\n\t\taws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])\n\n\t\tfrom prowler.providers.aws.services.awslambda.awslambda_service import Lambda\n\n\t\twith mock.patch(\n\t\t\t'prowler.providers.common.provider.Provider.get_global_provider',\n\t\t\treturn_value=aws_provider,\n\t\t), mock.patch(\n\t\t\t'prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client',\n\t\t\tnew=Lambda(aws_provider),\n\t\t):\n\t\t\t# Test Check\n\t\t\tfrom prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (\n\t\t\t\tawslambda_function_not_publicly_accessible,\n\t\t\t)\n\n\t\t\tcheck = awslambda_function_not_publicly_accessible()\n\t\t\tresult = check.execute()\n\n\t\t\tassert len(result) == 1\n\t\t\tassert result[0].region == AWS_REGION_EU_WEST_1\n\t\t\tassert result[0].resource_id == function_name\n\t\t\tassert result[0].resource_arn == function_arn\n\t\t\tassert result[0].status == 'PASS'\n\t\t\tassert (\n\t\t\t\tresult[0].status_extended\n\t\t\t\t== f'Lambda function {function_name} has a policy resource-based policy not public.'\n\t\t\t)\n\t\t\tassert result[0].resource_tags == [{'tag1': 'value1', 'tag2': 'value2'}]",
            f"{check_name}:",
        ]
        return prompt_parts

    def _prepare_metadata_prompt(self, metadata: dict, context: str) -> list:
        """Prepare the prompt for generating the metadata."""

        metadata.pop("SubServiceName", None)
        metadata["Remediation"]["Code"].pop("NativeIaC", None)
        metadata["Remediation"]["Code"].pop("Other", None)
        metadata["Remediation"]["Code"].pop("Terraform", None)
        metadata.pop("DependsOn", None)
        metadata.pop("RelatedTo", None)

        valid_prowler_categories = [
            "encryption",
            "forensics-ready",
            "internet-exposed",
            "logging",
            "redundancy",
            "secrets",
            "thread-detection",
            "trustboundaries",
            "vulnerability-management",
        ]

        metadata_placeholder_resource_type = get_metadata_placeholder_resource_type(
            metadata.get("Provider")
        )

        prompt_parts = [
            "Your task is to fill the metadata for a new cybersecurity check in Prowler (a Cloud Security tool).",
            "The metadata is a JSON object with the following fields: ",
            json.dumps(metadata, indent=2),
            "Use the following context sources as inspiration to fill the metadata: ",
            context,
            "The field CheckType should be filled following the format: 'namespace/category/classifier', where namespace, category, and classifier are the values from the following dict: ",
            json.dumps(
                get_metadata_valid_check_type(metadata.get("Provider")), indent=2
            ),
            "One example of a valid CheckType value is: 'Software and Configuration Checks/Vulnerabilities/CVE'. If you don't have a valid value for CheckType, you can leave it empty.",
            f"The field ResourceType must be one of the following values (if there is not a valid value, you can put '{metadata_placeholder_resource_type}'): ",
            ", ".join(get_metadata_valid_resource_type(metadata.get("Provider"))),
            "If you don't have a valid value for ResourceType, you can leave it empty.",
            f"The field Category must be one or more of the following values: {', '.join(valid_prowler_categories)}.",
            "I need the answer only with JSON formatted text.",
        ]
        return prompt_parts

    def generate_check(self, check_name: str, context: str) -> str:
        """Fill the check with Gemini AI."""
        check = ""

        prompt_parts = self._prepare_check_prompt(check_name, context)
        check = (
            self._generate_content(prompt_parts)
            .replace("python", "")
            .replace("```", "")
            .strip()
        )

        return check

    def generate_test(self, check_name: str):
        """Fill the test with Gemini AI."""
        test = ""

        prompt_parts = self._prepare_test_prompt(
            check_name,
        )
        test = (
            self._generate_content(prompt_parts)
            .replace("python", "")
            .replace("```", "")
            .strip()
        )

        return test

    def generate_metadata(self, metadata: dict, context: str) -> dict:
        """Fill the metadata with Gemini AI."""
        if not metadata:
            return {}

        prompt_parts = self._prepare_metadata_prompt(metadata, context)
        filled_metadata_json = self._generate_content(prompt_parts)

        # Parse the generated JSON and re-add the removed fields
        filled_metadata = json.loads(
            filled_metadata_json.replace("\n", "")
            .replace("json", "")
            .replace("JSON", "")
            .replace("```", "")
            .strip()
        )

        # Add the removed fields back in the same order
        filled_metadata["Remediation"]["Code"]["NativeIaC"] = ""
        filled_metadata["Remediation"]["Code"]["Other"] = ""
        filled_metadata["Remediation"]["Code"]["Terraform"] = ""

        # Insert key SubServiceName after ServiceName key and RelatedTo and DependsOn just before Notes key

        ordered_filled_metadata = {}

        for key, value in filled_metadata.items():
            if key == "Notes":
                ordered_filled_metadata["DependsOn"] = []
                ordered_filled_metadata["RelatedTo"] = []
            ordered_filled_metadata[key] = value
            if key == "ServiceName":
                ordered_filled_metadata["SubServiceName"] = ""

        # Check that resource type is valid
        if filled_metadata["ResourceType"]:
            valid_resource_types = get_metadata_valid_resource_type(
                filled_metadata["Provider"]
            )
            if filled_metadata["ResourceType"] not in valid_resource_types:
                ordered_filled_metadata["ResourceType"] = "Other"

        return ordered_filled_metadata
