from prowler.providers.image.lib.registry.dockerhub_adapter import DockerHubAdapter
from prowler.providers.image.lib.registry.factory import create_registry_adapter
from prowler.providers.image.lib.registry.oci_adapter import OciRegistryAdapter


class TestCreateRegistryAdapter:
    def test_docker_hub_returns_dockerhub_adapter(self):
        adapter = create_registry_adapter("docker.io/myorg")
        assert isinstance(adapter, DockerHubAdapter)

    def test_oci_returns_oci_adapter(self):
        adapter = create_registry_adapter("myregistry.io")
        assert isinstance(adapter, OciRegistryAdapter)

    def test_ecr_returns_oci_adapter(self):
        adapter = create_registry_adapter("123456789.dkr.ecr.us-east-1.amazonaws.com")
        assert isinstance(adapter, OciRegistryAdapter)

    def test_passes_credentials(self):
        adapter = create_registry_adapter(
            "myregistry.io",
            username="user",
            password="pass",
            token="tok",
            verify_ssl=False,
        )
        assert adapter.username == "user"
        assert adapter.password == "pass"
        assert adapter.token == "tok"
        assert adapter.verify_ssl is False

    def test_registry_1_docker_io(self):
        adapter = create_registry_adapter("registry-1.docker.io/myorg")
        assert isinstance(adapter, DockerHubAdapter)
