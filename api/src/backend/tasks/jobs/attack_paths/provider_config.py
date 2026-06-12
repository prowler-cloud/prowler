"""
Provider-level Attack Paths configuration.

Each `ProviderConfig` carries the cloud provider's ingestion entry point and
the catalog of list-typed node properties (`normalized_lists`). The sync
layer reads this catalog and materialises each list element as a child node
connected to the parent by a typed edge, so queries traverse the graph
instead of working on serialised list values. Both Neo4j and Neptune sinks
write the same shape and queries are portable across them.
"""

from dataclasses import dataclass, field
from typing import Callable

from tasks.jobs.attack_paths import aws


@dataclass(frozen=True)
class NormalizedList:
    """Catalog entry for a list-typed node property.

    Describes how the sync layer materialises a parent node's list-typed
    property as a set of child item nodes connected by a typed edge.

    Conventions (mechanical, do not invent):
      - `child_label`: `<SourceLabel><PropertyPascal>Item`
          e.g. AWSPolicyStatement.resource -> AWSPolicyStatementResourceItem
      - `rel_type`:    `HAS_<PROPERTY_UPPER>`
          e.g. resource -> HAS_RESOURCE
      - child node property:
          * `field_map = []` (scalar list, ~95% case)  -> child stores `value: str`
          * `field_map = [(src_key, child_field), ...]` (list of dicts, rare)
              -> child stores those fields
    """

    source_label: str
    source_property: str
    child_label: str
    rel_type: str
    field_map: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.field_map:
            child_fields = [dst for _, dst in self.field_map]
            if "value" in child_fields:
                raise ValueError(
                    f"NormalizedList {self.source_label}.{self.source_property}: "
                    "`value` is reserved for scalar mode; do not map a source key to it"
                )
            src_keys = [src for src, _ in self.field_map]
            if len(set(src_keys)) != len(src_keys):
                raise ValueError(
                    f"NormalizedList {self.source_label}.{self.source_property}: "
                    "duplicate source key in field_map"
                )
            if len(set(child_fields)) != len(child_fields):
                raise ValueError(
                    f"NormalizedList {self.source_label}.{self.source_property}: "
                    "duplicate child field in field_map"
                )


@dataclass(frozen=True)
class ProviderConfig:
    """Configuration for a cloud provider's Attack Paths integration."""

    name: str
    root_node_label: str  # e.g., "AWSAccount"
    uid_field: str  # e.g., "arn"
    # Label for resources connected to the account node, enabling indexed finding lookups
    resource_label: str  # e.g., "_AWSResource"
    ingestion_function: Callable
    # Maps a Postgres resource UID (e.g. full ARN) to the short-id form Cartography stores on some node types (e.g. `i-xxx` for EC2Instance)
    short_uid_extractor: Callable[[str], str]
    # List-typed properties to materialise as child nodes + edges at sync time.
    # Mandatory (may be []). Without an entry here, a list-typed property falls
    # back to comma-string flatten and emits a one-time warning.
    normalized_lists: list[NormalizedList]


# AWS list-typed property catalog.
# One entry per Cartography node property whose runtime value is a list. The
# sync layer materialises each element as a `<child_label>` node and links it
# to the parent with a `<rel_type>` edge; see the `NormalizedList` docstring
# above for the naming conventions.
AWS_NORMALIZED_LISTS: list[NormalizedList] = [
    # AWSPolicyStatement - the hot path driving the 53-query perf fix.
    NormalizedList(
        "AWSPolicyStatement", "action", "AWSPolicyStatementActionItem", "HAS_ACTION"
    ),
    NormalizedList(
        "AWSPolicyStatement",
        "notaction",
        "AWSPolicyStatementNotactionItem",
        "HAS_NOTACTION",
    ),
    NormalizedList(
        "AWSPolicyStatement",
        "resource",
        "AWSPolicyStatementResourceItem",
        "HAS_RESOURCE",
    ),
    NormalizedList(
        "AWSPolicyStatement",
        "notresource",
        "AWSPolicyStatementNotresourceItem",
        "HAS_NOTRESOURCE",
    ),
    # S3PolicyStatement - same shape as IAM policies; AWS allows list or string.
    NormalizedList(
        "S3PolicyStatement", "action", "S3PolicyStatementActionItem", "HAS_ACTION"
    ),
    NormalizedList(
        "S3PolicyStatement", "resource", "S3PolicyStatementResourceItem", "HAS_RESOURCE"
    ),
    # IAM / Cognito / KMS / Secrets
    NormalizedList(
        "CognitoIdentityPool", "roles", "CognitoIdentityPoolRolesItem", "HAS_ROLES"
    ),
    NormalizedList(
        "KMSKey",
        "encryption_algorithms",
        "KMSKeyEncryptionAlgorithmsItem",
        "HAS_ENCRYPTION_ALGORITHMS",
    ),
    NormalizedList(
        "KMSKey",
        "signing_algorithms",
        "KMSKeySigningAlgorithmsItem",
        "HAS_SIGNING_ALGORITHMS",
    ),
    NormalizedList(
        "KMSKey",
        "anonymous_actions",
        "KMSKeyAnonymousActionsItem",
        "HAS_ANONYMOUS_ACTIONS",
    ),
    NormalizedList(
        "KMSGrant", "operations", "KMSGrantOperationsItem", "HAS_OPERATIONS"
    ),
    NormalizedList(
        "SecretsManagerSecretVersion",
        "version_stages",
        "SecretsManagerSecretVersionVersionStagesItem",
        "HAS_VERSION_STAGES",
    ),
    NormalizedList(
        "SecretsManagerSecretVersion",
        "kms_key_ids",
        "SecretsManagerSecretVersionKmsKeyIdsItem",
        "HAS_KMS_KEY_IDS",
    ),
    NormalizedList(
        "SecretsManagerSecretVersion",
        "tags",
        "SecretsManagerSecretVersionTagsItem",
        "HAS_TAGS",
        field_map=[("Key", "key"), ("Value", "value_")],
        # `value` is reserved for scalar mode; map `Value` to `value_` to keep dict shape.
    ),
    # Lambda / Compute
    NormalizedList(
        "AWSLambda", "architectures", "AWSLambdaArchitecturesItem", "HAS_ARCHITECTURES"
    ),
    NormalizedList(
        "AWSLambda",
        "anonymous_actions",
        "AWSLambdaAnonymousActionsItem",
        "HAS_ANONYMOUS_ACTIONS",
    ),
    NormalizedList(
        "CodeBuildProject",
        "environment_variables",
        "CodeBuildProjectEnvironmentVariablesItem",
        "HAS_ENVIRONMENT_VARIABLES",
    ),
    # ECS family
    NormalizedList(
        "ECSCluster",
        "capacity_providers",
        "ECSClusterCapacityProvidersItem",
        "HAS_CAPACITY_PROVIDERS",
    ),
    NormalizedList(
        "ECSTaskDefinition",
        "compatibilities",
        "ECSTaskDefinitionCompatibilitiesItem",
        "HAS_COMPATIBILITIES",
    ),
    NormalizedList(
        "ECSTaskDefinition",
        "requires_compatibilities",
        "ECSTaskDefinitionRequiresCompatibilitiesItem",
        "HAS_REQUIRES_COMPATIBILITIES",
    ),
    NormalizedList(
        "ECSContainerDefinition",
        "links",
        "ECSContainerDefinitionLinksItem",
        "HAS_LINKS",
    ),
    NormalizedList(
        "ECSContainerDefinition",
        "entry_point",
        "ECSContainerDefinitionEntryPointItem",
        "HAS_ENTRY_POINT",
    ),
    NormalizedList(
        "ECSContainerDefinition",
        "command",
        "ECSContainerDefinitionCommandItem",
        "HAS_COMMAND",
    ),
    NormalizedList(
        "ECSContainerDefinition",
        "dns_servers",
        "ECSContainerDefinitionDnsServersItem",
        "HAS_DNS_SERVERS",
    ),
    NormalizedList(
        "ECSContainerDefinition",
        "dns_search_domains",
        "ECSContainerDefinitionDnsSearchDomainsItem",
        "HAS_DNS_SEARCH_DOMAINS",
    ),
    NormalizedList(
        "ECSContainerDefinition",
        "docker_security_options",
        "ECSContainerDefinitionDockerSecurityOptionsItem",
        "HAS_DOCKER_SECURITY_OPTIONS",
    ),
    NormalizedList("ECSContainer", "gpu_ids", "ECSContainerGpuIdsItem", "HAS_GPU_IDS"),
    # ECR
    NormalizedList(
        "ECRImage", "layer_diff_ids", "ECRImageLayerDiffIdsItem", "HAS_LAYER_DIFF_IDS"
    ),
    NormalizedList(
        "ECRImage",
        "child_image_digests",
        "ECRImageChildImageDigestsItem",
        "HAS_CHILD_IMAGE_DIGESTS",
    ),
    # EC2 / Networking
    NormalizedList(
        "EC2Instance",
        "exposed_internet_type",
        "EC2InstanceExposedInternetTypeItem",
        "HAS_EXPOSED_INTERNET_TYPE",
    ),
    NormalizedList(
        "AutoScalingGroup",
        "exposed_internet_type",
        "AutoScalingGroupExposedInternetTypeItem",
        "HAS_EXPOSED_INTERNET_TYPE",
    ),
    NormalizedList(
        "LaunchConfiguration",
        "security_groups",
        "LaunchConfigurationSecurityGroupsItem",
        "HAS_SECURITY_GROUPS",
    ),
    NormalizedList(
        "LaunchTemplateVersion",
        "security_group_ids",
        "LaunchTemplateVersionSecurityGroupIdsItem",
        "HAS_SECURITY_GROUP_IDS",
    ),
    NormalizedList(
        "LaunchTemplateVersion",
        "security_groups",
        "LaunchTemplateVersionSecurityGroupsItem",
        "HAS_SECURITY_GROUPS",
    ),
    NormalizedList(
        "ELBListener", "policy_names", "ELBListenerPolicyNamesItem", "HAS_POLICY_NAMES"
    ),
    # CloudFront / Route53 / CloudWatch / CloudTrail
    NormalizedList(
        "CloudFrontDistribution",
        "aliases",
        "CloudFrontDistributionAliasesItem",
        "HAS_ALIASES",
    ),
    NormalizedList(
        "CloudFrontDistribution",
        "geo_restriction_locations",
        "CloudFrontDistributionGeoRestrictionLocationsItem",
        "HAS_GEO_RESTRICTION_LOCATIONS",
    ),
    NormalizedList(
        "CloudWatchLogGroup",
        "inherited_properties",
        "CloudWatchLogGroupInheritedPropertiesItem",
        "HAS_INHERITED_PROPERTIES",
    ),
    # RDS / Storage
    NormalizedList(
        "RDSCluster",
        "availability_zones",
        "RDSClusterAvailabilityZonesItem",
        "HAS_AVAILABILITY_ZONES",
    ),
    NormalizedList(
        "RDSEventSubscription",
        "event_categories",
        "RDSEventSubscriptionEventCategoriesItem",
        "HAS_EVENT_CATEGORIES",
    ),
    NormalizedList(
        "RDSEventSubscription",
        "source_ids",
        "RDSEventSubscriptionSourceIdsItem",
        "HAS_SOURCE_IDS",
    ),
    NormalizedList(
        "S3Bucket",
        "anonymous_actions",
        "S3BucketAnonymousActionsItem",
        "HAS_ANONYMOUS_ACTIONS",
    ),
    # Inspector / Config / SSM / ACM / APIGateway / Glue / SageMaker / Bedrock
    NormalizedList(
        "AWSInspectorFinding",
        "referenceurls",
        "AWSInspectorFindingReferenceurlsItem",
        "HAS_REFERENCEURLS",
    ),
    NormalizedList(
        "AWSInspectorFinding",
        "relatedvulnerabilities",
        "AWSInspectorFindingRelatedvulnerabilitiesItem",
        "HAS_RELATEDVULNERABILITIES",
    ),
    NormalizedList(
        "AWSInspectorFinding",
        "vulnerablepackageids",
        "AWSInspectorFindingVulnerablepackageidsItem",
        "HAS_VULNERABLEPACKAGEIDS",
    ),
    NormalizedList(
        "AWSConfigurationRecorder",
        "recording_group_resource_types",
        "AWSConfigurationRecorderRecordingGroupResourceTypesItem",
        "HAS_RECORDING_GROUP_RESOURCE_TYPES",
    ),
    NormalizedList(
        "AWSConfigRule",
        "scope_compliance_resource_types",
        "AWSConfigRuleScopeComplianceResourceTypesItem",
        "HAS_SCOPE_COMPLIANCE_RESOURCE_TYPES",
    ),
    NormalizedList(
        "AWSConfigRule",
        "source_details",
        "AWSConfigRuleSourceDetailsItem",
        "HAS_SOURCE_DETAILS",
    ),
    NormalizedList(
        "SSMInstancePatch", "cve_ids", "SSMInstancePatchCveIdsItem", "HAS_CVE_IDS"
    ),
    NormalizedList(
        "ACMCertificate", "in_use_by", "ACMCertificateInUseByItem", "HAS_IN_USE_BY"
    ),
    NormalizedList(
        "APIGatewayRestAPI",
        "anonymous_actions",
        "APIGatewayRestAPIAnonymousActionsItem",
        "HAS_ANONYMOUS_ACTIONS",
    ),
    NormalizedList(
        "GlueJob", "connections", "GlueJobConnectionsItem", "HAS_CONNECTIONS"
    ),
    NormalizedList(
        "AWSBedrockFoundationModel",
        "input_modalities",
        "AWSBedrockFoundationModelInputModalitiesItem",
        "HAS_INPUT_MODALITIES",
    ),
    NormalizedList(
        "AWSBedrockFoundationModel",
        "output_modalities",
        "AWSBedrockFoundationModelOutputModalitiesItem",
        "HAS_OUTPUT_MODALITIES",
    ),
    NormalizedList(
        "AWSBedrockFoundationModel",
        "customizations_supported",
        "AWSBedrockFoundationModelCustomizationsSupportedItem",
        "HAS_CUSTOMIZATIONS_SUPPORTED",
    ),
    NormalizedList(
        "AWSBedrockFoundationModel",
        "inference_types_supported",
        "AWSBedrockFoundationModelInferenceTypesSupportedItem",
        "HAS_INFERENCE_TYPES_SUPPORTED",
    ),
]


AWS_CONFIG = ProviderConfig(
    name="aws",
    root_node_label="AWSAccount",
    uid_field="arn",
    resource_label="_AWSResource",
    ingestion_function=aws.start_aws_ingestion,
    short_uid_extractor=aws.extract_short_uid,
    normalized_lists=AWS_NORMALIZED_LISTS,
)


PROVIDER_CONFIGS: dict[str, ProviderConfig] = {
    "aws": AWS_CONFIG,
}
