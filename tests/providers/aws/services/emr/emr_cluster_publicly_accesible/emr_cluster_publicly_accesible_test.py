from unittest import mock
from uuid import uuid4

from boto3 import resource, session
from moto import mock_ec2
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.emr.emr_service import Cluster, ClusterStatus, Node

AWS_REGION = "eu-west-1"


class Test_emr_cluster_publicly_accesible:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

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

    @mock_ec2
    def test_clusters_master_public_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION)
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
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION,
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Master Node {master_expected_public_sgs}"
            )

    @mock_ec2
    def test_clusters_master_private_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION)
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
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION,
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is not publicly accessible"
            )

    @mock_ec2
    def test_clusters_master_private_slave_public_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION)
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
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION,
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Slaves Nodes {slave_expected_public_sgs}"
            )

    @mock_ec2
    def test_clusters_master_public_slave_private_two_sg(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION)
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
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION,
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Master Node {master_expected_public_sgs}"
            )

    @mock_ec2
    def test_clusters_master_private_slave_public_sg_none_additional_sgs(self):
        # EC2 Client
        ec2 = resource("ec2", AWS_REGION)
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
        cluster_arn = f"arn:aws:elasticmapreduce:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:cluster/{cluster_name}"
        emr_client.clusters = {
            "test-cluster": Cluster(
                id=cluster_id,
                arn=cluster_arn,
                name=cluster_name,
                status=ClusterStatus.RUNNING,
                region=AWS_REGION,
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.emr.emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import (
                emr_cluster_publicly_accesible,
            )

            check = emr_cluster_publicly_accesible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EMR Cluster {cluster_id} is publicly accessible through the following Security Groups: Slaves Nodes {slave_expected_public_sgs}"
            )
