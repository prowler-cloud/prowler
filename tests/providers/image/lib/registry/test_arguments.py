from argparse import Namespace

import pytest

from prowler.providers.image.lib.arguments.arguments import validate_arguments


class TestValidateArguments:
    def test_no_source_fails(self):
        args = Namespace(images=[], image_list_file=None, registry=None, image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "--image" in msg

    def test_image_only_passes(self):
        args = Namespace(images=["nginx:latest"], image_list_file=None, registry=None, image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, _ = validate_arguments(args)
        assert ok

    def test_image_list_only_passes(self):
        args = Namespace(images=[], image_list_file="images.txt", registry=None, image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, _ = validate_arguments(args)
        assert ok

    def test_registry_only_passes(self):
        args = Namespace(images=[], image_list_file=None, registry="myregistry.io", image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, _ = validate_arguments(args)
        assert ok

    def test_image_filter_without_registry_fails(self):
        args = Namespace(images=["nginx:latest"], image_list_file=None, registry=None, image_filter="^prod", tag_filter=None, max_images=0, registry_insecure=False)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "--image-filter requires --registry" in msg

    def test_tag_filter_without_registry_fails(self):
        args = Namespace(images=["nginx:latest"], image_list_file=None, registry=None, image_filter=None, tag_filter="^v", max_images=0, registry_insecure=False)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "--tag-filter requires --registry" in msg

    def test_max_images_without_registry_fails(self):
        args = Namespace(images=["nginx:latest"], image_list_file=None, registry=None, image_filter=None, tag_filter=None, max_images=50, registry_insecure=False)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "--max-images requires --registry" in msg

    def test_registry_insecure_without_registry_fails(self):
        args = Namespace(images=[], image_list_file="i.txt", registry=None, image_filter=None, tag_filter=None, max_images=0, registry_insecure=True)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "--registry-insecure requires --registry" in msg

    def test_docker_hub_no_namespace_fails(self):
        args = Namespace(images=[], image_list_file=None, registry="docker.io", image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "namespace" in msg.lower()

    def test_docker_hub_with_namespace_passes(self):
        args = Namespace(images=[], image_list_file=None, registry="docker.io/myorg", image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, _ = validate_arguments(args)
        assert ok

    def test_docker_hub_https_no_namespace_fails(self):
        args = Namespace(images=[], image_list_file=None, registry="https://docker.io", image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "namespace" in msg.lower()

    def test_registry_with_filters_passes(self):
        args = Namespace(images=[], image_list_file=None, registry="myregistry.io", image_filter="^prod", tag_filter="^v", max_images=100, registry_insecure=True)
        ok, _ = validate_arguments(args)
        assert ok

    def test_registry_list_without_registry_fails(self):
        args = Namespace(images=["nginx:latest"], image_list_file=None, registry=None, image_filter=None, tag_filter=None, max_images=0, registry_insecure=False, registry_list_images=True)
        ok, msg = validate_arguments(args)
        assert not ok
        assert "--registry-list requires --registry" in msg

    def test_registry_list_with_registry_passes(self):
        args = Namespace(images=[], image_list_file=None, registry="myregistry.io", image_filter=None, tag_filter=None, max_images=0, registry_insecure=False, registry_list_images=True)
        ok, _ = validate_arguments(args)
        assert ok

    def test_combined_registry_and_image_passes(self):
        args = Namespace(images=["nginx:latest"], image_list_file=None, registry="myregistry.io", image_filter=None, tag_filter=None, max_images=0, registry_insecure=False)
        ok, _ = validate_arguments(args)
        assert ok
