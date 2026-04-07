from prowler.lib.check.models import CheckMetadata, Code, Recommendation, Remediation

test_bulk_checks_metadata = {
    "vpc_peering_routing_tables_with_least_privilege": CheckMetadata(
        Provider="aws",
        CheckID="vpc_peering_routing_tables_with_least_privilege",
        CheckTitle="VPC peering routing tables should follow least access.",
        CheckType=[
            "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
        ],
        ServiceName="vpc",
        SubServiceName="route_table",
        ResourceIdTemplate="arn:partition:service:region:account-id:resource-id",
        Severity="medium",
        ResourceType="AwsEc2VpcPeeringConnection",
        Description="VPC peering routing tables should follow least access.",
        Risk="Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC.",
        RelatedUrl="",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="",
                Terraform="",
                CLI="aws ec2 create-route",
                Other="",
            ),
            Recommendation=Recommendation(
                Text="Review routing tables of peered VPCs for whether they route all subnets of each VPC and whether that is necessary to accomplish the intended purposes for peering the VPCs.",
                Url="https://hub.prowler.com/check/vpc_peering_routing_tables_with_least_privilege",
            ),
        ),
        Categories=["forensics-ready"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "vpc_subnet_different_az": CheckMetadata(
        Provider="aws",
        CheckID="vpc_subnet_different_az",
        CheckTitle="VPC should have subnets in more than one availability zone",
        CheckType=[
            "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
        ],
        ServiceName="vpc",
        SubServiceName="subnet",
        ResourceIdTemplate="arn:partition:service:region:account-id:resource-id",
        Severity="medium",
        ResourceType="AwsEc2Vpc",
        Description="Ensure all vpc has subnets in more than one availability zone",
        Risk="",
        RelatedUrl="",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="", Terraform="", CLI="aws ec2 create-subnet", Other=""
            ),
            Recommendation=Recommendation(
                Text="VPC should have subnets in more than one availability zone",
                Url="",
            ),
        ),
        Categories=["secrets"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "vpc_subnet_separate_private_public": CheckMetadata(
        Provider="aws",
        CheckID="vpc_subnet_separate_private_public",
        CheckTitle="VPC should have public and private subnets defined",
        CheckType=[
            "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
        ],
        ServiceName="vpc",
        SubServiceName="subnet",
        ResourceIdTemplate="arn:partition:service:region:account-id:resource-id",
        Severity="medium",
        ResourceType="AwsEc2Vpc",
        Description="Ensure all vpc has public and private subnets defined",
        Risk="",
        RelatedUrl="",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="", Terraform="", CLI="aws ec2 create-subnet", Other=""
            ),
            Recommendation=Recommendation(
                Text="VPC should have public and private subnets defined", Url=""
            ),
        ),
        Categories=["internet-exposed", "trust-boundaries"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "workspaces_volume_encryption_enabled": CheckMetadata(
        Provider="aws",
        CheckID="workspaces_volume_encryption_enabled",
        CheckTitle="Amazon WorkSpaces storage volumes should be encrypted",
        CheckType=[
            "Software and Configuration Checks/AWS Security Best Practices/Runtime Behavior Analysis"
        ],
        ServiceName="workspaces",
        SubServiceName="",
        ResourceIdTemplate="arn:aws:workspaces:region:account-id:workspace",
        Severity="high",
        ResourceType="AwsWorkspaces",
        Description="Amazon WorkSpaces storage volumes should be encrypted to meet security and compliance requirements",
        Risk="If the value listed in the Volume Encryption column is Disabled the selected AWS WorkSpaces instance volumes (root and user volumes) are not encrypted. Therefore your data-at-rest is not protected from unauthorized access and does not meet the compliance requirements regarding data encryption.",
        RelatedUrl="",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="https://docs.prowler.com/checks/ensure-that-workspace-root-volumes-are-encrypted#cloudformation",
                Terraform="https://docs.prowler.com/checks/ensure-that-workspace-root-volumes-are-encrypted#terraform",
                CLI="",
                Other="https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/WorkSpaces/storage-encryption.html",
            ),
            Recommendation=Recommendation(
                Text="WorkSpaces is integrated with the AWS Key Management Service (AWS KMS). This enables you to encrypt storage volumes of WorkSpaces using AWS KMS Key. When you launch a WorkSpace you can encrypt the root volume (for Microsoft Windows - the C drive; for Linux - /) and the user volume (for Windows - the D drive; for Linux - /home). Doing so ensures that the data stored at rest - disk I/O to the volume - and snapshots created from the volumes are all encrypted",
                Url="https://hub.prowler.com/check/workspaces_volume_encryption_enabled",
            ),
        ),
        Categories=["encryption"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "workspaces_vpc_2private_1public_subnets_nat": CheckMetadata(
        Provider="aws",
        CheckID="workspaces_vpc_2private_1public_subnets_nat",
        CheckTitle="Workspaces VPC should use 1 public and 2 private subnets with NAT Gateway",
        CheckType=[
            "Software and Configuration Checks/AWS Security Best Practices/Runtime Behavior Analysis"
        ],
        ServiceName="workspaces",
        SubServiceName="",
        ResourceIdTemplate="arn:aws:workspaces:region:account-id:workspace",
        Severity="medium",
        ResourceType="AwsWorkspaces",
        Description="Workspaces VPC should be deployed with 1 public subnet and 2 private subnets with a NAT Gateway attached",
        Risk="Proper network segmentation is a key security best practice. Workspaces VPC should be deployed using 1 public subnet and 2 private subnets with a NAT Gateway attached",
        RelatedUrl="",
        Remediation=Remediation(
            Code=Code(NativeIaC="", Terraform="", CLI="", Other=""),
            Recommendation=Recommendation(
                Text="Follow the documentation and deploy Workspaces VPC using 1 public subnet and 2 private subnets with a NAT Gateway attached",
                Url="https://hub.prowler.com/check/workspaces_vpc_2private_1public_subnets_nat",
            ),
        ),
        Categories=[],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
}
