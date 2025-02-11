from unittest import mock
from uuid import uuid4

from prowler.providers.nhn.services.compute.compute_service import Instance
from tests.providers.nhn.nhn_fixtures import set_mocked_nhn_provider

class Test_compute_instance_public_ip:
    def test_no_instances(self):
        # 1) Make a MagicMock for compute_client
        compute_client = mock.MagicMock()
        compute_client.instances = []

        # 2) Patch get_global_provider() to return a mocked NHN provider
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_nhn_provider(),
        ), mock.patch(
            # patch the 'compute_instance_public_ip.compute_client' used in the check code
            "prowler.providers.nhn.services.compute.compute_instance_public_ip.compute_instance_public_ip.compute_client",
            new=compute_client,
        ):
            # 3) Import the check code AFTER patching
            from prowler.providers.nhn.services.compute.compute_instance_public_ip.compute_instance_public_ip import (
                compute_instance_public_ip,
            )

            # 4) Run the check
            check = compute_instance_public_ip()
            result = check.execute()

            # 5) Assertions
            assert len(result) == 0  # no instances => no findings

    def test_has_instance_non_public_ip(self):
        # Make a MagicMock for compute_client
        compute_client = mock.MagicMock()
        
        # Suppose we have 1 instance with public_ip=False => PASS expected
        instance_id = str(uuid4())
        instance_name = "testVM"
        mock_instance = mock.MagicMock(spec=Instance)
        mock_instance.id = instance_id
        mock_instance.name = instance_name
        mock_instance.public_ip = False   # => means does not have public IP
        compute_client.instances = [mock_instance]
        # compute_client.instances = [
        #     mock.MagicMock(
        #         id=instance_id,
        #         name=instance_name,
        #         public_ip=False,   # => means does not have public IP
        #     )
        # ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_nhn_provider(),
        ), mock.patch(
            "prowler.providers.nhn.services.compute.compute_instance_public_ip.compute_instance_public_ip.compute_client",
            new=compute_client,
        ):
            from prowler.providers.nhn.services.compute.compute_instance_public_ip.compute_instance_public_ip import (
                compute_instance_public_ip,
            )
            check = compute_instance_public_ip()
            result = check.execute()
            
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have a public IP" in result[0].status_extended
            assert result[0].resource_name == instance_name
            assert result[0].resource_id == instance_id

    def test_has_instance_public_ip(self):
        # Another scenario: instance with public_ip=True => FAIL expected
        compute_client = mock.MagicMock()
        
        instance_id = str(uuid4())
        instance_name = "rootVM"
        mock_instance = mock.MagicMock(spec=Instance)
        mock_instance.id = instance_id
        mock_instance.name = instance_name
        mock_instance.public_ip = True   # => means has public IP
        compute_client.instances = [mock_instance]
        # compute_client.instances = [
        #     mock.MagicMock(
        #         id=instance_id,
        #         name=instance_name,
        #         public_ip=True,   # => means has public IP
        #     )
        # ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_nhn_provider(),
        ), mock.patch(
            "prowler.providers.nhn.services.compute.compute_instance_public_ip.compute_instance_public_ip.compute_client",
            new=compute_client,
        ):
            from prowler.providers.nhn.services.compute.compute_instance_public_ip.compute_instance_public_ip import (
                compute_instance_public_ip,
            )
            check = compute_instance_public_ip()
            result = check.execute()
            
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has a public IP" in result[0].status_extended
            assert result[0].resource_name == instance_name
            assert result[0].resource_id == instance_id
