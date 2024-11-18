def get_metadata_valid_check_type(provider: str = "aws") -> list:
    """Get the valid check types for the provider

    Args:
        provider: The Prowler provider.

    Returns:
        A list of valid check types for the given provider.
    """
    check_types = []

    if provider == "aws":
        check_types = [
            {
                "namespace": "Software and Configuration Checks",
                "children": [
                    {
                        "category": "Vulnerabilities",
                        "children": [{"classifier": "CVE"}],
                    },
                    {
                        "category": "AWS Security Best Practices",
                        "children": [
                            {"classifier": "Network Reachability"},
                            {"classifier": "Runtime Behavior Analysis"},
                        ],
                    },
                    {
                        "category": "Industry and Regulatory Standards",
                        "children": [
                            {"classifier": "AWS Foundational Security Best Practices"},
                            {"classifier": "CIS Host Hardening Benchmarks"},
                            {"classifier": "CIS AWS Foundations Benchmark"},
                            {"classifier": "PCI-DSS"},
                            {"classifier": "Cloud Security Alliance Controls"},
                            {"classifier": "ISO 90001 Controls"},
                            {"classifier": "ISO 27001 Controls"},
                            {"classifier": "ISO 27017 Controls"},
                            {"classifier": "ISO 27018 Controls"},
                            {"classifier": "SOC 1"},
                            {"classifier": "SOC 2"},
                            {"classifier": "HIPAA Controls (USA)"},
                            {"classifier": "NIST 800-53 Controls (USA)"},
                            {"classifier": "NIST CSF Controls (USA)"},
                            {"classifier": "IRAP Controls (Australia)"},
                            {"classifier": "K-ISMS Controls (Korea)"},
                            {"classifier": "MTCS Controls (Singapore)"},
                            {"classifier": "FISC Controls (Japan)"},
                            {"classifier": "My Number Act Controls (Japan)"},
                            {"classifier": "ENS Controls (Spain)"},
                            {"classifier": "Cyber Essentials Plus Controls (UK)"},
                            {"classifier": "G-Cloud Controls (UK)"},
                            {"classifier": "C5 Controls (Germany)"},
                            {"classifier": "IT-Grundschutz Controls (Germany)"},
                            {"classifier": "GDPR Controls (Europe)"},
                            {"classifier": "TISAX Controls (Europe)"},
                        ],
                    },
                    {"category": "Patch Management"},
                ],
            },
            {
                "namespace": "TTPs",
                "children": [
                    {"category": "Initial Access"},
                    {"category": "Execution"},
                    {"category": "Persistence"},
                    {"category": "Privilege Escalation"},
                    {"category": "Defense Evasion"},
                    {"category": "Credential Access"},
                    {"category": "Discovery"},
                    {"category": "Lateral Movement"},
                    {"category": "Collection"},
                    {"category": "Command and Control"},
                ],
            },
            {
                "namespace": "Effects",
                "children": [
                    {"category": "Data Exposure"},
                    {"category": "Data Exfiltration"},
                    {"category": "Data Destruction"},
                    {"category": "Denial of Service"},
                    {"category": "Resource Consumption"},
                ],
            },
            {
                "namespace": "Unusual Behaviors",
                "children": [
                    {"category": "Application"},
                    {"category": "Network Flow"},
                    {"category": "IP address"},
                    {"category": "User"},
                    {"category": "VM"},
                    {"category": "Container"},
                    {"category": "Serverless"},
                    {"category": "Process"},
                    {"category": "Database"},
                    {"category": "Data"},
                ],
            },
            {
                "namespace": "Sensitive Data Identifications",
                "children": [
                    {"category": "PII"},
                    {"category": "Passwords"},
                    {"category": "Legal"},
                    {"category": "Financial"},
                    {"category": "Security"},
                    {"category": "Business"},
                ],
            },
        ]

    return check_types


def get_metadata_valid_resource_type(provider: str = "aws") -> set:
    """Get the valid resource types for the provider

    Args:
        provider: The Prowler provider.

    Returns:
        A set of valid resource types for the given provider.
    """
    valid_resource_types = set()

    if provider == "aws":
        valid_resource_types = {
            "AwsIamAccessKey",
            "AwsElbLoadBalancer",
            "AwsRedshiftCluster",
            "AwsEventsEndpoint",
            "AwsElbv2LoadBalancer",
            "AwsAutoScalingLaunchConfiguration",
            "AwsWafv2RuleGroup",
            "AwsWafRegionalRule",
            "AwsCloudFrontDistribution",
            "AwsWafRegionalWebAcl",
            "AwsWafRateBasedRule",
            "AwsCertificateManagerCertificate",
            "AwsKmsKey",
            "AwsDmsEndpoint",
            "AwsLambdaLayerVersion",
            "AwsIamRole",
            "AwsElasticBeanstalkEnvironment",
            "AwsBackupBackupPlan",
            "AwsEc2ClientVpnEndpoint",
            "AwsEcrContainerImage",
            "AwsSqsQueue",
            "AwsIamGroup",
            "AwsOpenSearchServiceDomain",
            "AwsApiGatewayV2Api",
            "AwsCloudTrailTrail",
            "AwsWafWebAcl",
            "AwsEc2Subnet",
            "AwsEc2VpcPeeringConnection",
            "AwsEc2VpcEndpointService",
            "AwsCodeBuildProject",
            "AwsLambdaFunction",
            "AwsNetworkFirewallRuleGroup",
            "AwsDmsReplicationInstance",
            "AwsRdsEventSubscription",
            "AwsCloudWatchAlarm",
            "AwsS3AccountPublicAccessBlock",
            "AwsWafRegionalRateBasedRule",
            "AwsRdsDbInstance",
            "AwsEksCluster",
            "AwsXrayEncryptionConfig",
            "AwsWafv2WebAcl",
            "AwsWafRuleGroup",
            "AwsBackupBackupVault",
            "AwsKinesisStream",
            "AwsNetworkFirewallFirewallPolicy",
            "AwsEc2NetworkInterface",
            "AwsEcsTaskDefinition",
            "AwsMskCluster",
            "AwsApiGatewayRestApi",
            "AwsS3Object",
            "AwsRdsDbSnapshot",
            "AwsBackupRecoveryPoint",
            "AwsWafRule",
            "AwsS3AccessPoint",
            "AwsApiGatewayV2Stage",
            "AwsGuardDutyDetector",
            "AwsEfsAccessPoint",
            "AwsEcsContainer",
            "AwsEcsTask",
            "AwsS3Bucket",
            "AwsSageMakerNotebookInstance",
            "AwsNetworkFirewallFirewall",
            "AwsStepFunctionStateMachine",
            "AwsIamUser",
            "AwsAppSyncGraphQLApi",
            "AwsApiGatewayStage",
            "AwsEcrRepository",
            "AwsEcsService",
            "AwsEc2Vpc",
            "AwsAmazonMQBroker",
            "AwsWafRegionalRuleGroup",
            "AwsEventSchemasRegistry",
            "AwsRoute53HostedZone",
            "AwsEventsEventbus",
            "AwsDmsReplicationTask",
            "AwsEc2Instance",
            "AwsEcsCluster",
            "AwsRdsDbSecurityGroup",
            "AwsCloudFormationStack",
            "AwsSnsTopic",
            "AwsDynamoDbTable",
            "AwsRdsDbCluster",
            "AwsEc2Eip",
            "AwsEc2RouteTable",
            "AwsEc2TransitGateway",
            "AwsElasticSearchDomain",
            "AwsEc2LaunchTemplate",
            "AwsEc2Volume",
            "AwsAthenaWorkGroup",
            "AwsSecretsManagerSecret",
            "AwsEc2SecurityGroup",
            "AwsIamPolicy",
            "AwsSsmPatchCompliance",
            "AwsAutoScalingAutoScalingGroup",
            "AwsEc2NetworkAcl",
            "AwsRdsDbClusterSnapshot",
        }

    return valid_resource_types


def get_metadata_placeholder_resource_type(provider: str = "aws") -> str:
    """Get the placeholder for the resource type for the provider

    Args:
        provider: The Prowler provider.

    Returns:
        A placeholder for the resource type for the given provider.
    """
    placeholder = ""

    if provider == "aws":
        placeholder = "Other"

    return placeholder
