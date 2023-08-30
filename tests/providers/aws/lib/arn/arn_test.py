from pytest import raises

from prowler.providers.aws.lib.arn.arn import is_valid_arn, parse_iam_credentials_arn
from prowler.providers.aws.lib.arn.error import (
    RoleArnParsingEmptyResource,
    RoleArnParsingFailedMissingFields,
    RoleArnParsingIAMRegionNotEmpty,
    RoleArnParsingInvalidAccountID,
    RoleArnParsingInvalidResourceType,
    RoleArnParsingPartitionEmpty,
    RoleArnParsingServiceNotIAMnorSTS,
)
from prowler.providers.aws.lib.arn.models import ARN

ACCOUNT_ID = "123456789012"
RESOURCE_TYPE_ROLE = "role"
RESOUCE_TYPE_USER = "user"
IAM_ROLE = "test-role"
IAM_SERVICE = "iam"
COMMERCIAL_PARTITION = "aws"
CHINA_PARTITION = "aws-cn"
GOVCLOUD_PARTITION = "aws-us-gov"


class Test_ARN_Parsing:
    def test_ARN_model(self):
        # https://gist.github.com/cmawhorter/80bf94f12bf7516d50a7d61ed28859d3
        test_cases = [
            "arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment",
            "arn:aws:iam::123456789012:user/David",
            "arn:aws:rds:eu-west-1:123456789012:db:mysql-db",
            "arn:aws:s3:::my_corporate_bucket/exampleobject.png",
            "arn:aws:artifact:::report-package/Certifications and Attestations/SOC/*",
            "arn:aws:artifact:::report-package/Certifications and Attestations/ISO/*",
            "arn:aws:artifact:::report-package/Certifications and Attestations/PCI/*",
            # "arn:aws:autoscaling:us-east-1:123456789012:scalingPolicy:c7a27f55-d35e-4153-b044-8ca9155fc467:autoScalingGroupName/my-test-asg1:policyName/my-scaleout-policy",
            "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
            "arn:aws:cloudformation:us-east-1:123456789012:stack/MyProductionStack/abc9dbf0-43c2-11e3-a6e8-50fa526be49c",
            "arn:aws:cloudformation:us-east-1:123456789012:changeSet/MyProductionChangeSet/abc9dbf0-43c2-11e3-a6e8-50fa526be49c",
            "arn:aws:cloudsearch:us-east-1:123456789012:domain/imdb-movies",
            "arn:aws:cloudtrail:us-east-1:123456789012:trail/mytrailname",
            "arn:aws:events:us-east-1:*:*",
            "arn:aws:events:us-east-1:account-id:*",
            "arn:aws:events:us-east-1:account-id:rule/rule_name",
            "arn:aws:logs:us-east-1:*:*",
            "arn:aws:logs:us-east-1:account-id:*",
            "arn:aws:logs:us-east-1:account-id:log-group:log_group_name",
            "arn:aws:logs:us-east-1:account-id:log-group:log_group_name:*",
            "arn:aws:logs:us-east-1:account-id:log-group:log_group_name_prefix*",
            "arn:aws:logs:us-east-1:account-id:log-group:log_group_name:log-stream:log_stream_name",
            "arn:aws:logs:us-east-1:account-id:log-group:log_group_name:log-stream:log_stream_name_prefix*",
            "arn:aws:logs:us-east-1:account-id:log-group:log_group_name_prefix*:log-stream:log_stream_name_prefix*",
            "arn:aws:codebuild:us-east-1:123456789012:project/my-demo-project",
            "arn:aws:codebuild:us-east-1:123456789012:build/my-demo-project:7b7416ae-89b4-46cc-8236-61129df660ad",
            "arn:aws:codecommit:us-east-1:123456789012:MyDemoRepo",
            "arn:aws:codedeploy:us-east-1:123456789012:application:WordPress_App",
            "arn:aws:codedeploy:us-east-1:123456789012:instance/AssetTag*",
            "arn:aws:config:us-east-1:123456789012:config-rule/MyConfigRule",
            "arn:aws:codepipeline:us-east-1:123456789012:MyDemoPipeline",
            "arn:aws:directconnect:us-east-1:123456789012:dxcon/dxcon-fgase048",
            "arn:aws:directconnect:us-east-1:123456789012:dxvif/dxvif-fgrb110x",
            "arn:aws:dynamodb:us-east-1:123456789012:table/books_table",
            "arn:aws:ecr:us-east-1:123456789012:repository/my-repository",
            "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster",
            "arn:aws:ecs:us-east-1:123456789012:container-instance/403125b0-555c-4473-86b5-65982db28a6d",
            "arn:aws:ecs:us-east-1:123456789012:task-definition/hello_world:8",
            "arn:aws:ecs:us-east-1:123456789012:service/sample-webapp",
            "arn:aws:ecs:us-east-1:123456789012:task/1abf0f6d-a411-4033-b8eb-a4eed3ad252a",
            "arn:aws:ecs:us-east-1:123456789012:container/476e7c41-17f2-4c17-9d14-412566202c8a",
            "arn:aws:ec2:us-east-1:123456789012:dedicated-host/h-12345678",
            "arn:aws:ec2:us-east-1::image/ami-1a2b3c4d",
            "arn:aws:ec2:us-east-1:123456789012:instance/*",
            "arn:aws:ec2:us-east-1:123456789012:volume/*",
            "arn:aws:ec2:us-east-1:123456789012:volume/vol-1a2b3c4d",
            "arn:aws:elasticbeanstalk:us-east-1:123456789012:application/My App",
            "arn:aws:elasticbeanstalk:us-east-1:123456789012:applicationversion/My App/My Version",
            "arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment",
            "arn:aws:elasticbeanstalk:us-east-1::solutionstack/32bit Amazon Linux running Tomcat 7",
            "arn:aws:elasticbeanstalk:us-east-1:123456789012:configurationtemplate/My App/My Template",
            "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system-id/fs12345678",
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188",
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-load-balancer/50dc6c495c0c9188/f2f7dc8efc522ab2",
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener-rule/app/my-load-balancer/50dc6c495c0c9188/f2f7dc8efc522ab2/9683b2d02a6cabee",
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/73e2d6bc24d8a067",
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/my-load-balancer",
            "arn:aws:elastictranscoder:us-east-1:123456789012:preset/*",
            "arn:aws:elasticache:us-west-2:123456789012:cluster:myCluster",
            "arn:aws:elasticache:us-west-2:123456789012:snapshot:mySnapshot",
            "arn:aws:es:us-east-1:123456789012:domain/streaming-logs",
            "arn:aws:glacier:us-east-1:123456789012:vaults/examplevault",
            "arn:aws:glacier:us-east-1:123456789012:vaults/example*",
            "arn:aws:glacier:us-east-1:123456789012:vaults/*",
            "arn:aws:health:us-east-1::event/AWS_EC2_EXAMPLE_ID",
            "arn:aws:health:us-east-1:123456789012:entity/AVh5GGT7ul1arKr1sE1K",
            "arn:aws:iam::123456789012:root",
            "arn:aws:iam::123456789012:user/Bob",
            "arn:aws:iam::123456789012:user/division_abc/subdivision_xyz/Bob",
            "arn:aws:iam::123456789012:group/Developers",
            "arn:aws:iam::123456789012:group/division_abc/subdivision_xyz/product_A/Developers",
            "arn:aws:iam::123456789012:role/S3Access",
            "arn:aws:iam::123456789012:role/application_abc/component_xyz/S3Access",
            "arn:aws:iam::123456789012:policy/UsersManageOwnCredentials",
            "arn:aws:iam::123456789012:policy/division_abc/subdivision_xyz/UsersManageOwnCredentials",
            "arn:aws:iam::123456789012:instance-profile/Webserver",
            "arn:aws:sts::123456789012:federated-user/Bob",
            "arn:aws:sts::123456789012:assumed-role/Accounting-Role/Mary",
            "arn:aws:iam::123456789012:mfa/BobJonesMFA",
            "arn:aws:iam::123456789012:server-certificate/ProdServerCert",
            "arn:aws:iam::123456789012:server-certificate/division_abc/subdivision_xyz/ProdServerCert",
            "arn:aws:iam::123456789012:saml-provider/ADFSProvider",
            "arn:aws:iam::123456789012:oidc-provider/GoogleProvider",
            "arn:aws:iot:your-region:123456789012:cert/123a456b789c123d456e789f123a456b789c123d456e789f123a456b789c123c456d7",
            "arn:aws:iot::123456789012:policy/MyIoTPolicy",
            "arn:aws:iot:your-region:123456789012:rule/MyIoTRule",
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "arn:aws:kms:us-east-1:123456789012:alias/example-alias",
            "arn:aws:firehose:us-east-1:123456789012:deliverystream/example-stream-name",
            "arn:aws:kinesis:us-east-1:123456789012:stream/example-stream-name",
            "arn:aws:lambda:us-east-1:123456789012:function:ProcessKinesisRecords",
            "arn:aws:lambda:us-east-1:123456789012:function:ProcessKinesisRecords:your alias",
            "arn:aws:lambda:us-east-1:123456789012:function:ProcessKinesisRecords:1.0",
            "arn:aws:lambda:us-east-1:123456789012:event-source-mappings:kinesis-stream-arn",
            "arn:aws:machinelearning:us-east-1:123456789012:datasource/my-datasource-1",
            "arn:aws:machinelearning:us-east-1:123456789012:mlmodel/my-mlmodel",
            "arn:aws:machinelearning:us-east-1:123456789012:batchprediction/my-batchprediction",
            "arn:aws:machinelearning:us-east-1:123456789012:evaluation/my-evaluation",
            "arn:aws:polly:us-east-1:123456789012:lexicon/myLexicon",
            "arn:aws:redshift:us-east-1:123456789012:cluster:my-cluster",
            "arn:aws:redshift:us-east-1:123456789012:my-cluster/my-dbuser-name",
            "arn:aws:redshift:us-east-1:123456789012:parametergroup:my-parameter-group",
            "arn:aws:redshift:us-east-1:123456789012:securitygroup:my-public-group",
            "arn:aws:redshift:us-east-1:123456789012:snapshot:my-cluster/my-snapshot20130807",
            "arn:aws:redshift:us-east-1:123456789012:subnetgroup:my-subnet-10                    ",
            "arn:aws:rds:us-east-1:123456789012:db:mysql-db-instance1",
            "arn:aws:rds:us-east-1:123456789012:snapshot:my-snapshot2",
            "arn:aws:rds:us-east-1:123456789012:cluster:my-cluster1",
            "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:cluster1-snapshot7",
            "arn:aws:rds:us-east-1:123456789012:og:mysql-option-group1",
            "arn:aws:rds:us-east-1:123456789012:pg:mysql-repl-pg1",
            "arn:aws:rds:us-east-1:123456789012:cluster-pg:aurora-pg3",
            "arn:aws:rds:us-east-1:123456789012:secgrp:dev-secgrp2",
            "arn:aws:rds:us-east-1:123456789012:subgrp:prod-subgrp1",
            "arn:aws:rds:us-east-1:123456789012:es:monitor-events2",
            "arn:aws:route53:::hostedzone/Z148QEXAMPLE8V",
            "arn:aws:route53:::change/C2RDJ5EXAMPLE2",
            "arn:aws:route53:::change/*",
            "arn:aws:ssm:us-east-1:123456789012:document/highAvailabilityServerSetup",
            "arn:aws:sns:*:123456789012:my_corporate_topic",
            "arn:aws:sns:us-east-1:123456789012:my_corporate_topic:02034b43-fefa-4e07-a5eb-3be56f8c54ce",
            "arn:aws:sqs:us-east-1:123456789012:queue1",
            "arn:aws:s3:::my_corporate_bucket",
            "arn:aws:s3:::my_corporate_bucket/exampleobject.png",
            "arn:aws:s3:::my_corporate_bucket/*",
            "arn:aws:s3:::my_corporate_bucket/Development/*",
            "arn:aws:swf:us-east-1:123456789012:/domain/department1",
            "arn:aws:swf:*:123456789012:/domain/*",
            "arn:aws:states:us-east-1:123456789012:activity:HelloActivity",
            "arn:aws:states:us-east-1:123456789012:stateMachine:HelloStateMachine",
            "arn:aws:states:us-east-1:123456789012:execution:HelloStateMachine:HelloStateMachineExecution",
            "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B",
            "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B/volume/vol-1122AABB",
            "arn:aws:storagegateway:us-east-1:123456789012:tape/AMZNC8A26D",
            "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B/target/iqn.1997-05.com.amazon:vol-1122AABB",
            "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B/device/AMZN_SGW-FF22CCDD_TAPEDRIVE_00010",
            "arn:aws:trustedadvisor:*:123456789012:checks/fault_tolerance/BueAdJ7NrP",
            "arn:aws:waf::123456789012:rule/41b5b052-1e4a-426b-8149-3595be6342c2",
            "arn:aws:waf::123456789012:webacl/3bffd3ed-fa2e-445e-869f-a6a7cf153fd3",
            "arn:aws:waf::123456789012:ipset/3f74bd8c-f046-4970-a1a7-41aa52e05480",
            "arn:aws:waf::123456789012:bytematchset/d131bc0b-57be-4536-af1d-4894fd28acc4",
            "arn:aws:waf::123456789012:sqlinjectionset/2be79d6f-2f41-4c9b-8192-d719676873f0",
            "arn:aws:waf::123456789012:changetoken/03ba2197-fc98-4ac0-a67d-5b839762b16b",
            "arn:aws:iam::123456789012:user/Development/product_1234/*",
            "arn:aws:s3:::my_corporate_bucket/*",
            "arn:aws:s3:::my_corporate_bucket/Development/*",
        ]
        # For now we are only testing that the ARN library does not raise any exception with the above list of ARNs.
        for arn in test_cases:
            _ = ARN(arn)

    def test_iam_credentials_arn_parsing(self):
        test_cases = [
            {
                "input_arn": f"arn:aws:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOURCE_TYPE_ROLE}/{IAM_ROLE}",
                "expected": {
                    "partition": COMMERCIAL_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOURCE_TYPE_ROLE,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:aws:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOUCE_TYPE_USER}/{IAM_ROLE}",
                "expected": {
                    "partition": COMMERCIAL_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOUCE_TYPE_USER,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{CHINA_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOURCE_TYPE_ROLE}/{IAM_ROLE}",
                "expected": {
                    "partition": CHINA_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOURCE_TYPE_ROLE,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{CHINA_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOUCE_TYPE_USER}/{IAM_ROLE}",
                "expected": {
                    "partition": CHINA_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOUCE_TYPE_USER,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{GOVCLOUD_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOURCE_TYPE_ROLE}/{IAM_ROLE}",
                "expected": {
                    "partition": GOVCLOUD_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOURCE_TYPE_ROLE,
                    "resource": IAM_ROLE,
                },
            },
            {
                "input_arn": f"arn:{GOVCLOUD_PARTITION}:{IAM_SERVICE}::{ACCOUNT_ID}:{RESOUCE_TYPE_USER}/{IAM_ROLE}",
                "expected": {
                    "partition": GOVCLOUD_PARTITION,
                    "service": IAM_SERVICE,
                    "region": None,
                    "account_id": ACCOUNT_ID,
                    "resource_type": RESOUCE_TYPE_USER,
                    "resource": IAM_ROLE,
                },
            },
        ]
        for test in test_cases:
            input_arn = test["input_arn"]
            parsed_arn = parse_iam_credentials_arn(input_arn)
            assert parsed_arn.partition == test["expected"]["partition"]
            assert parsed_arn.service == test["expected"]["service"]
            assert parsed_arn.region == test["expected"]["region"]
            assert parsed_arn.account_id == test["expected"]["account_id"]
            assert parsed_arn.resource_type == test["expected"]["resource_type"]
            assert parsed_arn.resource == test["expected"]["resource"]

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingFailedMissingFields(
        self,
    ):
        input_arn = ""
        with raises(RoleArnParsingFailedMissingFields) as error:
            parse_iam_credentials_arn(input_arn)

        assert error._excinfo[0] == RoleArnParsingFailedMissingFields

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingIAMRegionNotEmpty(self):
        input_arn = "arn:aws:iam:eu-west-1:111111111111:user/prowler"
        with raises(RoleArnParsingIAMRegionNotEmpty) as error:
            parse_iam_credentials_arn(input_arn)

        assert error._excinfo[0] == RoleArnParsingIAMRegionNotEmpty

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingPartitionEmpty(self):
        input_arn = "arn::iam::111111111111:user/prowler"
        with raises(RoleArnParsingPartitionEmpty) as error:
            parse_iam_credentials_arn(input_arn)

        assert error._excinfo[0] == RoleArnParsingPartitionEmpty

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingServiceNotIAM(self):
        input_arn = "arn:aws:s3::111111111111:user/prowler"
        with raises(RoleArnParsingServiceNotIAMnorSTS) as error:
            parse_iam_credentials_arn(input_arn)

        assert error._excinfo[0] == RoleArnParsingServiceNotIAMnorSTS

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingInvalidAccountID(self):
        input_arn = "arn:aws:iam::AWS_ACCOUNT_ID:user/prowler"
        with raises(RoleArnParsingInvalidAccountID) as error:
            parse_iam_credentials_arn(input_arn)

        assert error._excinfo[0] == RoleArnParsingInvalidAccountID

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingInvalidResourceType(
        self,
    ):
        input_arn = "arn:aws:iam::111111111111:account/prowler"
        with raises(RoleArnParsingInvalidResourceType) as error:
            parse_iam_credentials_arn(input_arn)

        assert error._excinfo[0] == RoleArnParsingInvalidResourceType

    def test_iam_credentials_arn_parsing_raising_RoleArnParsingEmptyResource(self):
        input_arn = "arn:aws:iam::111111111111:role/"
        with raises(RoleArnParsingEmptyResource) as error:
            parse_iam_credentials_arn(input_arn)

        assert error._excinfo[0] == RoleArnParsingEmptyResource

    def test_is_valid_arn(self):
        assert is_valid_arn("arn:aws:iam::012345678910:user/test")
        assert is_valid_arn("arn:aws-cn:ec2:us-east-1:123456789012:vpc/vpc-12345678")
        assert is_valid_arn("arn:aws-us-gov:s3:::bucket")
        assert is_valid_arn("arn:aws-iso:iam::012345678910:user/test")
        assert is_valid_arn("arn:aws-iso-b:ec2:us-east-1:123456789012:vpc/vpc-12345678")
        assert is_valid_arn(
            "arn:aws:lambda:eu-west-1:123456789012:function:lambda-function"
        )
        assert is_valid_arn("arn:aws:sns:eu-west-1:123456789012:test.fifo")
        assert not is_valid_arn("arn:azure:::012345678910:user/test")
        assert not is_valid_arn("arn:aws:iam::account:user/test")
        assert not is_valid_arn("arn:aws:::012345678910:resource")
