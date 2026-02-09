from argparse import Namespace
from unittest.mock import patch

from prowler.providers.common.arguments import validate_elasticsearch_arguments


class TestValidateElasticsearchArguments:
    def test_elasticsearch_disabled(self):
        args = Namespace(elasticsearch=False)
        valid, error = validate_elasticsearch_arguments(args)
        assert valid is True
        assert error == ""

    def test_elasticsearch_no_flag(self):
        args = Namespace()
        valid, error = validate_elasticsearch_arguments(args)
        assert valid is True
        assert error == ""

    def test_elasticsearch_enabled_with_url_and_api_key(self):
        args = Namespace(
            elasticsearch=True,
            elasticsearch_url="https://localhost:9200",
            elasticsearch_api_key="test-key",
            elasticsearch_username=None,
            elasticsearch_password=None,
        )
        valid, error = validate_elasticsearch_arguments(args)
        assert valid is True
        assert error == ""

    def test_elasticsearch_enabled_with_url_and_basic_auth(self):
        args = Namespace(
            elasticsearch=True,
            elasticsearch_url="https://localhost:9200",
            elasticsearch_api_key=None,
            elasticsearch_username="elastic",
            elasticsearch_password="changeme",
        )
        valid, error = validate_elasticsearch_arguments(args)
        assert valid is True
        assert error == ""

    def test_elasticsearch_enabled_no_url(self):
        args = Namespace(
            elasticsearch=True,
            elasticsearch_url=None,
            elasticsearch_api_key="test-key",
            elasticsearch_username=None,
            elasticsearch_password=None,
        )
        with patch.dict("os.environ", {}, clear=True):
            valid, error = validate_elasticsearch_arguments(args)
        assert valid is False
        assert "URL is required" in error

    def test_elasticsearch_enabled_no_auth(self):
        args = Namespace(
            elasticsearch=True,
            elasticsearch_url="https://localhost:9200",
            elasticsearch_api_key=None,
            elasticsearch_username=None,
            elasticsearch_password=None,
        )
        with patch.dict("os.environ", {}, clear=True):
            valid, error = validate_elasticsearch_arguments(args)
        assert valid is False
        assert "requires either" in error

    def test_elasticsearch_enabled_username_without_password(self):
        args = Namespace(
            elasticsearch=True,
            elasticsearch_url="https://localhost:9200",
            elasticsearch_api_key=None,
            elasticsearch_username="elastic",
            elasticsearch_password=None,
        )
        with patch.dict("os.environ", {}, clear=True):
            valid, error = validate_elasticsearch_arguments(args)
        assert valid is False
        assert "requires either" in error

    def test_elasticsearch_url_from_env(self):
        args = Namespace(
            elasticsearch=True,
            elasticsearch_url=None,
            elasticsearch_api_key="test-key",
            elasticsearch_username=None,
            elasticsearch_password=None,
        )
        with patch.dict(
            "os.environ", {"ELASTICSEARCH_URL": "https://localhost:9200"}, clear=False
        ):
            valid, error = validate_elasticsearch_arguments(args)
        assert valid is True

    def test_elasticsearch_api_key_from_env(self):
        args = Namespace(
            elasticsearch=True,
            elasticsearch_url="https://localhost:9200",
            elasticsearch_api_key=None,
            elasticsearch_username=None,
            elasticsearch_password=None,
        )
        with patch.dict(
            "os.environ", {"ELASTICSEARCH_API_KEY": "env-key"}, clear=False
        ):
            valid, error = validate_elasticsearch_arguments(args)
        assert valid is True


class TestElasticsearchParserArgs:
    def setup_method(self):
        self.patch_get_available_providers = patch(
            "prowler.providers.common.provider.Provider.get_available_providers",
            new=lambda: [
                "aws",
                "azure",
                "gcp",
                "kubernetes",
                "m365",
                "github",
                "iac",
                "nhn",
                "mongodbatlas",
                "oraclecloud",
                "alibabacloud",
                "cloudflare",
                "openstack",
            ],
        )
        self.patch_get_available_providers.start()

        from prowler.lib.cli.parser import ProwlerArgumentParser

        self.parser = ProwlerArgumentParser()

    def teardown_method(self):
        self.patch_get_available_providers.stop()

    def test_elasticsearch_flag(self):
        command = [
            "prowler",
            "aws",
            "--elasticsearch",
            "--elasticsearch-url",
            "https://localhost:9200",
            "--elasticsearch-api-key",
            "key",
        ]
        parsed = self.parser.parse(command)
        assert parsed.elasticsearch is True

    def test_elasticsearch_default_index(self):
        command = [
            "prowler",
            "aws",
            "--elasticsearch",
            "--elasticsearch-url",
            "https://localhost:9200",
            "--elasticsearch-api-key",
            "key",
        ]
        parsed = self.parser.parse(command)
        assert parsed.elasticsearch_index == "prowler-findings"

    def test_elasticsearch_custom_index(self):
        command = [
            "prowler",
            "aws",
            "--elasticsearch",
            "--elasticsearch-url",
            "https://localhost:9200",
            "--elasticsearch-api-key",
            "key",
            "--elasticsearch-index",
            "custom-index",
        ]
        parsed = self.parser.parse(command)
        assert parsed.elasticsearch_index == "custom-index"

    def test_elasticsearch_skip_tls_verify(self):
        command = [
            "prowler",
            "aws",
            "--elasticsearch",
            "--elasticsearch-url",
            "https://localhost:9200",
            "--elasticsearch-api-key",
            "key",
            "--elasticsearch-skip-tls-verify",
        ]
        parsed = self.parser.parse(command)
        assert parsed.elasticsearch_skip_tls_verify is True

    def test_send_es_only_fails(self):
        command = [
            "prowler",
            "aws",
            "--elasticsearch",
            "--elasticsearch-url",
            "https://localhost:9200",
            "--elasticsearch-api-key",
            "key",
            "--send-es-only-fails",
        ]
        parsed = self.parser.parse(command)
        assert parsed.send_es_only_fails is True

    def test_elasticsearch_defaults_off(self):
        command = ["prowler", "aws"]
        parsed = self.parser.parse(command)
        assert parsed.elasticsearch is False
        assert parsed.elasticsearch_url is None
        assert parsed.elasticsearch_skip_tls_verify is False
        assert parsed.send_es_only_fails is False
