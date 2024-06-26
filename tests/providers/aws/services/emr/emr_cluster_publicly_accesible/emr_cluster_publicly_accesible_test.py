from unittest import mock
from uuid import uuid4

from boto3 import resource
from moto import mock_aws

from prowler.providers.aws.services.emr.emr_service import Cluster, ClusterStatus, Node
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_emr_cluster_publicly_accesible:
    def test_no_clusters(self):
        # EMR Client
        emr_client = mock.MagicMock
        emr_client.clusters = {}
        # EC2 Client
        ec2_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_service.EC2",
            new=ec2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_clusters_master_public_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION_EU_WEST_1)
        # Create Security Group
        master_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        master_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="0.0.0.0/0",
        )

        # EMR Client
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="test.amazonaws.com",
                public=True,
                master=Node(
                    security_group_id=master_security_group.id,
                    additional_security_groups_id=[],
                ),
            )
        }

        master_expected_public_sgs = [master_security_group.id]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(set_mocked_aws_provider()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Master Node {master_expected_public_sgs}"
            )

    @mock_aws
    def test_clusters_master_private_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION_EU_WEST_1)
        # Create Security Group
        master_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        master_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="10.0.0.0/8",
        )

        # EMR Client
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="test.amazonaws.com",
                public=True,
                master=Node(
                    security_group_id=master_security_group.id,
                    additional_security_groups_id=[],
                ),
            )
        }

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(set_mocked_aws_provider()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is not publicly accessible."
            )

    @mock_aws
    def test_clusters_master_private_slave_public_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION_EU_WEST_1)
        # Create Master Security Group
        master_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        master_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="10.0.0.0/8",
        )

        # Create Slave Security Group
        slave_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        slave_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="0.0.0.0/0",
        )

        # EMR Client
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="test.amazonaws.com",
                public=True,
                master=Node(
                    security_group_id=master_security_group.id,
                    additional_security_groups_id=[],
                ),
                slave=Node(
                    security_group_id=slave_security_group.id,
                    additional_security_groups_id=[],
                ),
            )
        }

        slave_expected_public_sgs = [slave_security_group.id]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(set_mocked_aws_provider()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Slaves Nodes {slave_expected_public_sgs}"
            )

    @mock_aws
    def test_clusters_master_public_slave_private_two_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION_EU_WEST_1)
        # Create Master Security Group
        master_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        master_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="0.0.0.0/0",
        )

        # Create Slave Security Group
        slave_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        slave_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="10.0.0.0/8",
        )

        # EMR Client
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="test.amazonaws.com",
                public=True,
                master=Node(
                    security_group_id=master_security_group.id,
                    additional_security_groups_id=[master_security_group.id],
                ),
                slave=Node(
                    security_group_id=slave_security_group.id,
                    additional_security_groups_id=[slave_security_group.id],
                ),
            )
        }

        master_expected_public_sgs = [
            master_security_group.id,
            master_security_group.id,
        ]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(set_mocked_aws_provider()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Master Node {master_expected_public_sgs}"
            )

    @mock_aws
    def test_clusters_master_private_slave_public_sg_none_additional_sgs(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION_EU_WEST_1)
        # Create Master Security Group
        master_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        master_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="10.0.0.0/8",
        )

        # Create Slave Security Group
        slave_security_group = ec2.create_security_group(
            GroupName=str(uuid4()), Description="test-decurity-group"
        )
        slave_security_group.authorize_ingress(
            IpProtocol="tcp",
            FromPort=0,
            ToPort=65535,
            CidrIp="0.0.0.0/0",
        )

        # EMR Client
        emr_client = mock.MagicMock
        cluster_name = "test-cluster"
        cluster_id = "j-XWO1UKVCC6FCV"
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION_EU_WEST_1,
                master_public_dns_name="test.amazonaws.com",
                public=True,
                master=Node(
                    security_group_id=master_security_group.id,
                    additional_security_groups_id=None,
                ),
                slave=Node(
                    security_group_id=slave_security_group.id,
                    additional_security_groups_id=None,
                ),
            )
        }

        slave_expected_public_sgs = [slave_security_group.id]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.emr.emr_service.EMR",
            new=emr_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(set_mocked_aws_provider()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Slaves Nodes {slave_expected_public_sgs}"
            )
