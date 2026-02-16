from unittest.mock import patch

import pytest

from prowler.providers.image.lib.registry.dockerhub_adapter import DockerHubAdapter
from prowler.providers.image.lib.registry.factory import (
    create_registry_adapter,
    detect_registry_type,
)
from prowler.providers.image.lib.registry.oci_adapter import OciRegistryAdapter


class TestDetectRegistryType:
    def test_generic_oci(self):
        assert detect_registry_type("myregistry.io") == "oci"

    def test_generic_oci_with_https(self):
        assert detect_registry_type("https://myregistry.io") == "oci"

    def test_docker_hub(self):
        assert detect_registry_type("docker.io/myorg") == "dockerhub"

    def test_docker_hub_registry1(self):
        assert detect_registry_type("registry-1.docker.io/myorg") == "dockerhub"

    def test_docker_hub_with_https(self):
        assert detect_registry_type("https://docker.io/myorg") == "dockerhub"

    def test_ecr(self):
        assert detect_registry_type("123456789.dkr.ecr.us-east-1.amazonaws.com") == "ecr"

    def test_ecr_with_https(self):
        assert detect_registry_type("https://123456789.dkr.ecr.us-east-1.amazonaws.com") == "ecr"

    def test_harbor(self):
        assert detect_registry_type("harbor.example.com") == "oci"


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
            "myregistry.io", username="user", password="pass", token="tok", verify_ssl=False
        )
        assert adapter.username == "user"
        assert adapter.password == "pass"
        assert adapter.token == "tok"
        assert adapter.verify_ssl is False

    def test_registry_1_docker_io(self):
        adapter = create_registry_adapter("registry-1.docker.io/myorg")
        assert isinstance(adapter, DockerHubAdapter)
