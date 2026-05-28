from unittest.mock import MagicMock

from prowler.providers.linode.services.instance.instance_service import (
    InstanceService,
)


def _mock_instance(
    id=1,
    label="my-instance",
    region="us-east",
    status="running",
    ipv4=None,
    backups_enabled=True,
    disk_encryption="enabled",
    watchdog_enabled=True,
    firewalls=None,
    tags=None,
):
    inst = MagicMock()
    inst.id = id
    inst.label = label
    region_mock = MagicMock()
    region_mock.id = region
    inst.region = region_mock
    inst.status = status
    inst.ipv4 = ipv4 or ["192.0.2.1"]
    backups = MagicMock()
    backups.enabled = backups_enabled
    inst.backups = backups
    inst.disk_encryption = disk_encryption
    inst.watchdog_enabled = watchdog_enabled
    inst.tags = tags or []
    # Use a dedicated MagicMock for the firewalls method
    firewalls_mock = MagicMock()
    firewalls_mock.return_value = firewalls or []
    inst.firewalls = firewalls_mock
    return inst


def _build_service(linode_instances_return=None, linode_instances_side_effect=None):
    """Build an InstanceService with an isolated mock client."""
    service = object.__new__(InstanceService)
    service.instances = []

    # Build isolated mock hierarchy for client.linode.instances()
    # Must explicitly create the instances callable as a fresh MagicMock
    # because check tests contaminate MagicMock class with instances=[...]
    instances_callable = MagicMock()
    if linode_instances_side_effect:
        instances_callable.side_effect = linode_instances_side_effect
    else:
        instances_callable.return_value = linode_instances_return or []

    linode_mock = MagicMock()
    linode_mock.instances = instances_callable

    client_mock = MagicMock()
    client_mock.linode = linode_mock
    service.client = client_mock
    return service


class TestLinodeInstanceService:
    def test_describe_instances_parses_correctly(self):
        mock_instances = [
            _mock_instance(
                id=1, label="web-1", region="us-east", firewalls=[MagicMock()]
            ),
            _mock_instance(id=2, label="db-1", region="eu-west", backups_enabled=False),
        ]

        service = _build_service(linode_instances_return=mock_instances)
        service._describe_instances()

        assert len(service.instances) == 2
        assert service.instances[0].label == "web-1"
        assert service.instances[0].region == "us-east"
        assert service.instances[0].firewalls_count == 1
        assert service.instances[0].backups_enabled is True
        assert service.instances[1].label == "db-1"
        assert service.instances[1].backups_enabled is False

    def test_describe_instances_handles_empty_list(self):
        service = _build_service(linode_instances_return=[])
        service._describe_instances()

        assert len(service.instances) == 0

    def test_describe_instances_handles_api_error(self):
        service = _build_service(linode_instances_side_effect=Exception("API error"))
        service._describe_instances()

        assert len(service.instances) == 0

    def test_describe_instances_disk_encryption(self):
        mock_instances = [
            _mock_instance(id=1, disk_encryption="enabled"),
            _mock_instance(id=2, disk_encryption="disabled"),
        ]

        service = _build_service(linode_instances_return=mock_instances)
        service._describe_instances()

        assert service.instances[0].disk_encryption == "enabled"
        assert service.instances[1].disk_encryption == "disabled"
