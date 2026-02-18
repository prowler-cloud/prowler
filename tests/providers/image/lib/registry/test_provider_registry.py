import os
from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.image.exceptions.exceptions import (
    ImageInvalidFilterError,
    ImageMaxImagesExceededError,
)
from prowler.providers.image.image_provider import ImageProvider
from prowler.providers.image.lib.registry.dockerhub_adapter import DockerHubAdapter

_CLEAN_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "HOME": os.environ.get("HOME", ""),
}


def _build_provider(**overrides):
    defaults = dict(
        images=[],
        registry="myregistry.io",
        image_filter=None,
        tag_filter=None,
        max_images=0,
        registry_insecure=False,
        registry_list_images=False,
        config_content={"image": {}},
    )
    defaults.update(overrides)
    with patch.dict(os.environ, _CLEAN_ENV, clear=True):
        return ImageProvider(**defaults)


class TestRegistryEnumeration:
    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_enumerate_oci_registry(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["app/frontend", "app/backend"]
        adapter.list_tags.side_effect = [["latest", "v1.0"], ["latest"]]
        mock_factory.return_value = adapter

        provider = _build_provider()
        assert "myregistry.io/app/frontend:latest" in provider.images
        assert "myregistry.io/app/frontend:v1.0" in provider.images
        assert "myregistry.io/app/backend:latest" in provider.images
        assert len(provider.images) == 3

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_image_filter(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["prod/app", "dev/app", "staging/app"]
        adapter.list_tags.return_value = ["latest"]
        mock_factory.return_value = adapter

        provider = _build_provider(image_filter="^prod/")
        assert len(provider.images) == 1
        assert "myregistry.io/prod/app:latest" in provider.images

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_tag_filter(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["myapp"]
        adapter.list_tags.return_value = ["latest", "v1.0", "v2.0", "dev-abc123"]
        mock_factory.return_value = adapter

        provider = _build_provider(tag_filter=r"^v\d+\.\d+$")
        assert len(provider.images) == 2
        assert "myregistry.io/myapp:v1.0" in provider.images
        assert "myregistry.io/myapp:v2.0" in provider.images

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_combined_filters(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["prod/app", "dev/app"]
        adapter.list_tags.return_value = ["latest", "v1.0"]
        mock_factory.return_value = adapter

        provider = _build_provider(image_filter="^prod/", tag_filter="^v")
        assert len(provider.images) == 1
        assert "myregistry.io/prod/app:v1.0" in provider.images


class TestMaxImages:
    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_max_images_exceeded(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["app1", "app2", "app3"]
        adapter.list_tags.return_value = ["latest", "v1.0"]
        mock_factory.return_value = adapter

        with pytest.raises(ImageMaxImagesExceededError):
            _build_provider(max_images=2)

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_max_images_not_exceeded(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["app1"]
        adapter.list_tags.return_value = ["latest"]
        mock_factory.return_value = adapter

        provider = _build_provider(max_images=10)
        assert len(provider.images) == 1


class TestDeduplication:
    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_deduplication_with_explicit_images(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["myapp"]
        adapter.list_tags.return_value = ["latest"]
        mock_factory.return_value = adapter

        provider = _build_provider(images=["myregistry.io/myapp:latest"])
        assert provider.images.count("myregistry.io/myapp:latest") == 1


class TestInvalidFilters:
    def test_invalid_image_filter_regex(self):
        with pytest.raises(ImageInvalidFilterError):
            _build_provider(image_filter="[invalid")

    def test_invalid_tag_filter_regex(self):
        with pytest.raises(ImageInvalidFilterError):
            _build_provider(tag_filter="(unclosed")


class TestRegistryInsecure:
    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_insecure_passes_verify_false(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["app"]
        adapter.list_tags.return_value = ["latest"]
        mock_factory.return_value = adapter

        _build_provider(registry_insecure=True)
        mock_factory.assert_called_once()
        call_kwargs = mock_factory.call_args[1]
        assert call_kwargs["verify_ssl"] is False


class TestEmptyRegistry:
    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_empty_catalog_with_explicit_images(self, mock_factory):
        adapter = MagicMock()
        adapter.list_repositories.return_value = []
        mock_factory.return_value = adapter

        provider = _build_provider(images=["nginx:latest"])
        assert provider.images == ["nginx:latest"]


class TestRegistryList:
    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_registry_list_prints_and_returns(self, mock_factory, capsys):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["app/frontend", "app/backend"]
        adapter.list_tags.side_effect = [["latest", "v1.0"], ["latest"]]
        mock_factory.return_value = adapter

        provider = _build_provider(registry_list_images=True)

        assert provider._listing_only is True
        captured = capsys.readouterr()
        assert "app/frontend" in captured.out
        assert "app/backend" in captured.out
        assert "latest" in captured.out
        assert "v1.0" in captured.out
        assert "2 repositories" in captured.out
        assert "3 images" in captured.out

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_registry_list_respects_image_filter(self, mock_factory, capsys):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["prod/app", "dev/app"]
        adapter.list_tags.return_value = ["latest"]
        mock_factory.return_value = adapter

        provider = _build_provider(registry_list_images=True, image_filter="^prod/")

        assert provider._listing_only is True
        captured = capsys.readouterr()
        assert "prod/app" in captured.out
        assert "dev/app" not in captured.out
        assert "1 repository" in captured.out

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_registry_list_respects_tag_filter(self, mock_factory, capsys):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["myapp"]
        adapter.list_tags.return_value = ["latest", "v1.0", "dev-abc"]
        mock_factory.return_value = adapter

        provider = _build_provider(registry_list_images=True, tag_filter=r"^v\d+\.\d+$")

        assert provider._listing_only is True
        captured = capsys.readouterr()
        assert "v1.0" in captured.out
        assert "dev-abc" not in captured.out
        assert "1 image)" in captured.out

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_registry_list_skips_max_images(self, mock_factory, capsys):
        adapter = MagicMock()
        adapter.list_repositories.return_value = ["app1", "app2", "app3"]
        adapter.list_tags.return_value = ["latest", "v1.0"]
        mock_factory.return_value = adapter

        # max_images=1 would normally raise, but --registry-list skips it
        provider = _build_provider(registry_list_images=True, max_images=1)

        assert provider._listing_only is True
        captured = capsys.readouterr()
        assert "6 images" in captured.out


class TestDockerHubEnumeration:
    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_dockerhub_images_use_repo_tag_format(self, mock_factory):
        """Docker Hub images should use repo:tag format without host prefix."""
        adapter = MagicMock(spec=DockerHubAdapter)
        adapter.list_repositories.return_value = ["myorg/app1", "myorg/app2"]
        adapter.list_tags.side_effect = [["latest", "v1.0"], ["latest"]]
        mock_factory.return_value = adapter

        provider = _build_provider(registry="docker.io/myorg")
        # Docker Hub images should NOT have host prefix
        assert "myorg/app1:latest" in provider.images
        assert "myorg/app1:v1.0" in provider.images
        assert "myorg/app2:latest" in provider.images
        # Ensure no host prefix was added
        for img in provider.images:
            assert not img.startswith("docker.io/"), f"Unexpected host prefix in {img}"
        assert len(provider.images) == 3
