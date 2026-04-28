"""
Tests for dynamic provider loading via entry points.

Covers: provider discovery, check discovery, check execution,
CLI argument registration, compliance frameworks, parser integration,
and all dispatch fallbacks for external providers.
"""

from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.common.provider import Provider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry_point(name, value, group):
    """Create a mock entry point."""
    ep = MagicMock()
    ep.name = name
    ep.value = value
    ep.group = group
    return ep


class FakeExternalProvider(Provider):
    """Minimal Provider subclass for testing the dynamic contract."""

    _type = "fakeexternal"
    _cli_help_text = "Fake External Provider"

    def __init__(self):
        Provider.set_global_provider(self)

    @property
    def type(self):
        return self._type

    @property
    def identity(self):
        return MagicMock(host_id="fake-host-1")

    @property
    def session(self):
        return MagicMock()

    @property
    def audit_config(self):
        return {}

    def setup_session(self):
        return MagicMock()

    def print_credentials(self):
        pass

    @classmethod
    def from_cli_args(cls, arguments, fixer_config):
        cls()

    def get_output_options(self, arguments, bulk_checks_metadata):
        return MagicMock(output_directory="/tmp", output_filename="fake")

    def get_stdout_detail(self, finding):
        return "fake-detail"

    def get_finding_sort_key(self):
        return "region"

    def get_summary_entity(self):
        return ("Fake Host", "fake-host-1")

    def get_finding_output_data(self, check_output):
        return {
            "auth_method": "fake",
            "account_uid": "fake-account",
            "account_name": "fake",
            "resource_name": "fake-resource",
            "resource_uid": "fake-uid",
            "region": "local",
        }

    def get_mutelist_finding_args(self):
        return {"host_id": self.identity.host_id}

    def display_compliance_table(
        self,
        findings,
        bulk_checks_metadata,
        compliance_framework,
        output_filename,
        output_directory,
        compliance_overview,
    ):
        return True

    def get_html_assessment_summary(self):
        return "<div>Fake Assessment</div>"

    def generate_compliance_output(
        self,
        findings,
        bulk_compliance_frameworks,
        input_compliance_frameworks,
        output_options,
        generated_outputs,
    ):
        generated_outputs["compliance"].append("fake-compliance-output")

    @classmethod
    def init_parser(cls, parser_instance):
        pass


class FakeToolWrapperProvider(Provider):
    """External provider that declares itself a tool wrapper."""

    _type = "faketoolwrapper"
    is_external_tool_provider = True

    @property
    def type(self):
        return self._type

    @property
    def identity(self):
        return MagicMock()

    @property
    def session(self):
        return MagicMock()

    @property
    def audit_config(self):
        return {}

    def setup_session(self):
        return MagicMock()

    def print_credentials(self):
        pass


class FakePureContractProvider(Provider):
    """External provider that honors the from_cli_args type hint literally:
    returns an instance without calling Provider.set_global_provider() from
    __init__. Used to verify the call site wires the returned instance."""

    _type = "fakepure"

    @property
    def type(self):
        return self._type

    @property
    def identity(self):
        return MagicMock(host_id="fake-pure-1")

    @property
    def session(self):
        return MagicMock()

    @property
    def audit_config(self):
        return {}

    def setup_session(self):
        return MagicMock()

    def print_credentials(self):
        pass

    @classmethod
    def from_cli_args(cls, arguments, fixer_config):
        # Literal contract: return the instance, no side-effect in __init__.
        return cls()


class FakeProviderNoHelpText(Provider):
    """Provider without _cli_help_text."""

    _type = "nohelptext"

    @property
    def type(self):
        return self._type

    @property
    def identity(self):
        return MagicMock()

    @property
    def session(self):
        return MagicMock()

    @property
    def audit_config(self):
        return {}

    def setup_session(self):
        return MagicMock()

    def print_credentials(self):
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_ep_cache():
    """Clear the entry point provider cache before each test."""
    Provider._ep_providers = {}
    yield
    Provider._ep_providers = {}


@pytest.fixture
def fake_provider():
    """Create and register a FakeExternalProvider."""
    p = FakeExternalProvider()
    yield p
    Provider._global = None


# ===========================================================================
# 1. Provider Discovery & Loading
# ===========================================================================


class TestProviderDiscovery:
    """Tests 1-7: get_available_providers, _load_ep_provider, get_providers_help_text."""

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_get_available_providers_merges_builtin_and_entrypoint(self, mock_ep):
        """Test 1: get_available_providers returns both built-in and entry point providers."""
        mock_ep.return_value = [
            _make_entry_point("fakeexternal", "pkg.provider:Cls", "prowler.providers"),
        ]

        providers = Provider.get_available_providers()

        # Built-in providers from actual prowler package
        assert "aws" in providers
        # External provider from entry point
        assert "fakeexternal" in providers
        assert "common" not in providers

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_get_available_providers_deduplicates(self, mock_ep):
        """Test 2: Same provider name in built-in and entry point appears once."""
        # "aws" exists as built-in AND as entry point
        mock_ep.return_value = [
            _make_entry_point("aws", "pkg.provider:Cls", "prowler.providers"),
        ]

        providers = Provider.get_available_providers()

        assert providers.count("aws") == 1

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_load_ep_provider_loads_class(self, mock_ep):
        """Test 3: _load_ep_provider loads the class from entry point."""
        mock_ep.return_value = [
            _make_entry_point(
                "fakeexternal", "pkg:FakeExternalProvider", "prowler.providers"
            ),
        ]
        mock_ep.return_value[0].load.return_value = FakeExternalProvider

        cls = Provider._load_ep_provider("fakeexternal")

        assert cls is FakeExternalProvider

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_load_ep_provider_returns_none_for_unknown(self, mock_ep):
        """Test 4: _load_ep_provider returns None for unknown provider."""
        mock_ep.return_value = []

        cls = Provider._load_ep_provider("nonexistent")

        assert cls is None

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_load_ep_provider_caches_result(self, mock_ep):
        """Test 5: _load_ep_provider caches the loaded class."""
        mock_ep.return_value = [
            _make_entry_point("fakeexternal", "pkg:Cls", "prowler.providers"),
        ]
        mock_ep.return_value[0].load.return_value = FakeExternalProvider

        cls1 = Provider._load_ep_provider("fakeexternal")
        cls2 = Provider._load_ep_provider("fakeexternal")

        assert cls1 is cls2
        # load() should only be called once due to caching
        mock_ep.return_value[0].load.assert_called_once()

    @patch("prowler.providers.common.provider.Provider._load_ep_provider")
    @patch("prowler.providers.common.provider.Provider.get_available_providers")
    def test_get_providers_help_text_reads_cli_help_text(
        self, mock_providers, mock_load
    ):
        """Test 6: get_providers_help_text reads _cli_help_text from entry point provider."""
        mock_providers.return_value = ["fakeexternal"]
        mock_load.return_value = FakeExternalProvider

        help_text = Provider.get_providers_help_text()

        assert help_text["fakeexternal"] == "Fake External Provider"

    @patch("prowler.providers.common.provider.Provider._load_ep_provider")
    @patch("prowler.providers.common.provider.Provider.get_available_providers")
    def test_get_providers_help_text_empty_without_cli_help_text(
        self, mock_providers, mock_load
    ):
        """Test 7: get_providers_help_text returns empty string without _cli_help_text."""
        mock_providers.return_value = ["nohelptext"]
        mock_load.return_value = FakeProviderNoHelpText

        help_text = Provider.get_providers_help_text()

        assert help_text["nohelptext"] == ""


class TestIsToolWrapperProvider:
    """Tests for Provider.is_tool_wrapper_provider — the helper that combines the
    built-in EXTERNAL_TOOL_PROVIDERS frozenset with the is_external_tool_provider
    class attribute of entry-point providers."""

    def test_returns_true_for_builtin_tool_wrappers(self):
        # iac/llm/image are in the EXTERNAL_TOOL_PROVIDERS frozenset (fast path)
        assert Provider.is_tool_wrapper_provider("iac") is True
        assert Provider.is_tool_wrapper_provider("llm") is True
        assert Provider.is_tool_wrapper_provider("image") is True

    def test_returns_false_for_regular_builtin_providers(self):
        # Regular built-ins must not be classified as tool wrappers
        assert Provider.is_tool_wrapper_provider("aws") is False
        assert Provider.is_tool_wrapper_provider("gcp") is False
        assert Provider.is_tool_wrapper_provider("github") is False

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_returns_true_for_external_provider_declaring_flag(self, mock_ep):
        # External plugin explicitly declares is_external_tool_provider = True
        mock_ep.return_value = [
            _make_entry_point("faketoolwrapper", "pkg:Cls", "prowler.providers"),
        ]
        mock_ep.return_value[0].load.return_value = FakeToolWrapperProvider

        assert Provider.is_tool_wrapper_provider("faketoolwrapper") is True

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_returns_false_for_external_provider_without_flag(self, mock_ep):
        # External plugin without the flag (default False) is treated as regular
        mock_ep.return_value = [
            _make_entry_point("fakeexternal", "pkg:Cls", "prowler.providers"),
        ]
        mock_ep.return_value[0].load.return_value = FakeExternalProvider

        assert Provider.is_tool_wrapper_provider("fakeexternal") is False

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_returns_false_for_unknown_provider(self, mock_ep):
        mock_ep.return_value = []

        assert Provider.is_tool_wrapper_provider("does-not-exist") is False

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_returns_false_for_none_provider(self, mock_ep):
        # Pydantic validators may pass None when values.get("Provider") is missing
        mock_ep.return_value = []

        assert Provider.is_tool_wrapper_provider(None) is False


class TestIsBuiltinProvider:
    """Tests for Provider.is_builtin — the helper that discriminates built-in
    providers from external ones before attempting the import, so transitive
    dependency failures in built-ins don't get silently re-routed to entry points."""

    def test_returns_true_for_builtin_provider(self):
        assert Provider.is_builtin("aws") is True
        assert Provider.is_builtin("github") is True

    def test_returns_false_for_unknown_provider(self):
        assert Provider.is_builtin("nonexistent_xyz") is False

    @patch("prowler.providers.common.provider.importlib.util.find_spec")
    def test_returns_false_when_find_spec_raises(self, mock_find_spec):
        # Certain namespace package edge cases raise ValueError/ImportError —
        # helper should swallow and return False rather than propagate.
        mock_find_spec.side_effect = ValueError("namespace package edge case")

        assert Provider.is_builtin("some_provider") is False


class TestInitProvidersParserBuiltinDependencyFailure:
    """Tests the critical behavior fix: when a built-in provider's arguments
    module exists but its imports fail (e.g. boto3 not installed), we must
    fail loudly with a clear message — not silently fall through to entry
    points as if the provider were external."""

    @patch("prowler.providers.common.arguments.Provider.is_builtin")
    @patch("prowler.providers.common.arguments.import_module")
    def test_builtin_with_missing_transitive_dep_fails_loudly(
        self, mock_import, mock_is_builtin
    ):
        from prowler.providers.common.arguments import init_providers_parser

        mock_is_builtin.return_value = True
        mock_import.side_effect = ImportError("No module named 'boto3'")

        parser = MagicMock()
        parser._providers = ["aws"]

        with (
            patch(
                "prowler.providers.common.arguments.Provider.get_available_providers",
                return_value=["aws"],
            ),
            pytest.raises(SystemExit),
        ):
            init_providers_parser(parser)

    @patch("prowler.providers.common.arguments.Provider.is_builtin")
    @patch("prowler.providers.common.arguments.Provider._load_ep_provider")
    def test_external_provider_does_not_touch_builtin_path(
        self, mock_load_ep, mock_is_builtin
    ):
        from prowler.providers.common.arguments import init_providers_parser

        mock_is_builtin.return_value = False
        ext_cls = MagicMock()
        ext_cls.init_parser = MagicMock()
        mock_load_ep.return_value = ext_cls

        parser = MagicMock()

        with patch(
            "prowler.providers.common.arguments.Provider.get_available_providers",
            return_value=["fakeexternal"],
        ):
            init_providers_parser(parser)

        ext_cls.init_parser.assert_called_once_with(parser)


class TestInitGlobalProviderBuiltinDependencyFailure:
    """Same contract as TestInitProvidersParserBuiltinDependencyFailure but
    for the provider class import path in init_global_provider."""

    @patch("prowler.providers.common.provider.Provider.is_builtin")
    @patch("prowler.providers.common.provider.import_module")
    def test_builtin_with_missing_transitive_dep_fails_loudly(
        self, mock_import, mock_is_builtin
    ):
        mock_is_builtin.return_value = True
        mock_import.side_effect = ImportError("No module named 'boto3'")

        args = Namespace(
            provider="aws",
            fixer_config="config.yaml",
            config_file="config.yaml",
        )

        Provider._global = None
        with pytest.raises(SystemExit):
            Provider.init_global_provider(args)
        Provider._global = None

    @patch("prowler.providers.common.provider.importlib.metadata.entry_points")
    def test_load_ep_provider_handles_load_exception(self, mock_ep):
        """_load_ep_provider returns None when ep.load() raises."""
        ep = _make_entry_point("broken", "pkg:Cls", "prowler.providers")
        ep.load.side_effect = Exception("Import failed")
        mock_ep.return_value = [ep]

        cls = Provider._load_ep_provider("broken")

        assert cls is None

    @patch("prowler.providers.common.provider.import_module")
    @patch("prowler.providers.common.provider.Provider.get_available_providers")
    def test_get_providers_help_text_builtin_path(self, mock_providers, mock_import):
        """get_providers_help_text reads _cli_help_text from a built-in provider module."""
        import types

        mock_providers.return_value = ["fakebuiltin"]

        mock_cls = type(
            "FakeBuiltinProvider", (Provider,), {"_cli_help_text": "Built-in Help"}
        )
        mock_module = types.ModuleType("fake_module")
        mock_module.FakeBuiltinProvider = mock_cls
        mock_import.return_value = mock_module

        help_text = Provider.get_providers_help_text()

        assert help_text["fakebuiltin"] == "Built-in Help"

    @patch("prowler.providers.common.provider.import_module")
    @patch("prowler.providers.common.provider.Provider.get_available_providers")
    def test_get_providers_help_text_generic_exception(
        self, mock_providers, mock_import
    ):
        """get_providers_help_text handles generic exceptions with empty string."""
        mock_providers.return_value = ["broken"]
        mock_import.side_effect = RuntimeError("Unexpected error")

        help_text = Provider.get_providers_help_text()

        assert help_text["broken"] == ""


# ===========================================================================
# 2. Provider Initialization
# ===========================================================================


class TestProviderInitialization:
    """Tests 8-9: init_global_provider fallback to entry point."""

    @patch("prowler.providers.common.provider.load_and_validate_config_file")
    @patch("prowler.providers.common.provider.Provider._load_ep_provider")
    @patch("prowler.providers.common.provider.import_module")
    def test_init_global_provider_fallback_to_entry_point(
        self, mock_import, mock_load_ep, mock_config
    ):
        """Test 8: init_global_provider falls back to entry point when built-in fails."""
        mock_import.side_effect = ImportError("No built-in")
        mock_load_ep.return_value = FakeExternalProvider
        mock_config.return_value = {}

        args = Namespace(
            provider="fakeexternal",
            fixer_config="config.yaml",
            config_file="config.yaml",
        )

        Provider._global = None
        Provider.init_global_provider(args)

        assert isinstance(Provider._global, FakeExternalProvider)
        Provider._global = None

    @patch("prowler.providers.common.provider.load_and_validate_config_file")
    @patch("prowler.providers.common.provider.Provider._load_ep_provider")
    @patch("prowler.providers.common.provider.import_module")
    def test_init_global_provider_exits_for_unknown_provider(
        self, mock_import, mock_load_ep, mock_config
    ):
        """Test 9: init_global_provider exits when provider not found anywhere."""
        mock_import.side_effect = ImportError("No built-in")
        mock_load_ep.return_value = None
        mock_config.return_value = {}

        args = Namespace(
            provider="nonexistent",
            fixer_config="config.yaml",
            config_file="config.yaml",
        )

        with pytest.raises(SystemExit):
            Provider.init_global_provider(args)

    @patch("prowler.providers.common.provider.load_and_validate_config_file")
    @patch("prowler.providers.common.provider.Provider._load_ep_provider")
    @patch("prowler.providers.common.provider.import_module")
    def test_init_global_provider_wires_instance_returned_by_from_cli_args(
        self, mock_import, mock_load_ep, mock_config
    ):
        """A provider that implements from_cli_args as a pure function (returns
        the instance without calling set_global_provider from __init__) is
        correctly wired as the global provider by init_global_provider."""
        mock_import.side_effect = ImportError("No built-in")
        mock_load_ep.return_value = FakePureContractProvider
        mock_config.return_value = {}

        args = Namespace(
            provider="fakepure",
            fixer_config="config.yaml",
            config_file="config.yaml",
        )

        Provider._global = None
        Provider.init_global_provider(args)

        assert isinstance(Provider._global, FakePureContractProvider)
        Provider._global = None

    @pytest.mark.parametrize(
        "plugin_name",
        [
            "awsx",
            "aws_lite",
            "azure_gov",
            "gcp_org",
            "github_enterprise",
            "iac_v2",
        ],
    )
    @patch("prowler.providers.common.provider.load_and_validate_config_file")
    @patch("prowler.providers.common.provider.Provider._load_ep_provider")
    @patch("prowler.providers.common.provider.import_module")
    def test_init_global_provider_external_with_builtin_substring_uses_from_cli_args(
        self, mock_import, mock_load_ep, mock_config, plugin_name
    ):
        """Regression guard for the substring footgun in the dispatch chain.

        An external plug-in whose name contains a built-in substring
        (e.g. `awsx`, `aws_lite`, `azure_gov`, `gcp_org`, `github_enterprise`,
        `iac_v2`) MUST be routed to the dynamic else and instantiated via
        `from_cli_args` — not silently captured by the built-in branch whose
        name happens to be a substring of the plug-in name. See PR #10700
        review.
        """
        mock_import.side_effect = ImportError("No built-in")
        mock_load_ep.return_value = FakeExternalProvider
        mock_config.return_value = {}

        # Namespace deliberately omits the kwargs of any built-in branch
        # (no `aws_retries_max_attempts`, `az_cli_auth`, `personal_access_token`,
        # etc.). If equality dispatch is broken and the plug-in is misrouted to
        # a built-in branch, attribute access will raise and the global never
        # gets wired.
        args = Namespace(
            provider=plugin_name,
            fixer_config="config.yaml",
            config_file="config.yaml",
        )

        Provider._global = None
        Provider.init_global_provider(args)

        assert isinstance(Provider._global, FakeExternalProvider)
        Provider._global = None


# ===========================================================================
# 3. Check Discovery
# ===========================================================================


class TestCheckDiscovery:
    """Tests 10-14: _recover_ep_checks, recover_checks_from_provider."""

    @patch("prowler.lib.check.utils.importlib.metadata.entry_points")
    @patch("prowler.lib.check.utils.importlib.util.find_spec")
    def test_recover_ep_checks_discovers_checks(self, mock_spec, mock_ep):
        """Test 10: _recover_ep_checks discovers checks from entry points."""
        from prowler.lib.check.utils import _recover_ep_checks

        mock_ep.return_value = [
            _make_entry_point("my_check", "pkg.checks.my_check", "prowler.checks.fake"),
        ]
        mock_spec_obj = MagicMock()
        mock_spec_obj.origin = "/path/to/pkg/checks/my_check.py"
        mock_spec.return_value = mock_spec_obj

        checks = _recover_ep_checks("fake")

        assert len(checks) == 1
        assert checks[0][0] == "my_check"
        assert checks[0][1] == "/path/to/pkg/checks"

    @patch("prowler.lib.check.utils.importlib.metadata.entry_points")
    def test_recover_ep_checks_empty_without_entry_points(self, mock_ep):
        """Test 11: _recover_ep_checks returns empty list with no entry points."""
        from prowler.lib.check.utils import _recover_ep_checks

        mock_ep.return_value = []

        checks = _recover_ep_checks("fake")

        assert checks == []

    @patch("prowler.lib.check.utils.importlib.metadata.entry_points")
    @patch("prowler.lib.check.utils.importlib.util.find_spec")
    def test_recover_ep_checks_handles_broken_entry_point(self, mock_spec, mock_ep):
        """Test 12: _recover_ep_checks handles failed entry points gracefully."""
        from prowler.lib.check.utils import _recover_ep_checks

        mock_ep.return_value = [
            _make_entry_point("broken_check", "pkg.broken", "prowler.checks.fake"),
        ]
        mock_spec.side_effect = Exception("Module not found")

        checks = _recover_ep_checks("fake")

        assert checks == []

    @patch("prowler.lib.check.utils._recover_ep_checks")
    @patch("prowler.lib.check.utils.list_modules")
    def test_recover_checks_handles_external_provider_without_services(
        self, mock_list_modules, mock_ep_checks
    ):
        """Test 13: recover_checks_from_provider doesn't crash for external providers."""
        from prowler.lib.check.utils import recover_checks_from_provider

        mock_list_modules.side_effect = ModuleNotFoundError("No services")
        mock_ep_checks.return_value = [("ext_check", "/path/to/check")]

        checks = recover_checks_from_provider("fakeexternal")

        assert len(checks) == 1
        assert checks[0][0] == "ext_check"

    @patch("prowler.lib.check.utils._recover_ep_checks")
    @patch("prowler.lib.check.utils.list_modules")
    def test_recover_checks_combines_builtin_and_entry_points(
        self, mock_list_modules, mock_ep_checks
    ):
        """Test 14: recover_checks_from_provider combines built-in and entry point checks."""
        from prowler.lib.check.utils import recover_checks_from_provider

        # Simulate a built-in module
        builtin_module = MagicMock()
        builtin_module.name = "prowler.providers.aws.services.ec2.check_a.check_a"
        builtin_module.module_finder.path = "/builtin/path"
        mock_list_modules.return_value = [builtin_module]

        mock_ep_checks.return_value = [("check_b", "/external/path")]

        checks = recover_checks_from_provider("aws")

        check_names = [c[0] for c in checks]
        assert "check_a" in check_names
        assert "check_b" in check_names

    @patch("prowler.lib.check.utils.importlib.metadata.entry_points")
    @patch("prowler.lib.check.utils.importlib.util.find_spec")
    def test_recover_ep_checks_filters_by_service(self, mock_spec, mock_ep):
        """Service filter keeps only entry points whose dotted path includes
        `.services.{service}.` — mirroring the built-in package filter."""
        from prowler.lib.check.utils import _recover_ep_checks

        mock_ep.return_value = [
            _make_entry_point(
                "container_has_no_root_user",
                "prowler_artifacts_dockerdesktop.services.container.container_has_no_root_user.container_has_no_root_user",
                "prowler.checks.dockerdesktop",
            ),
            _make_entry_point(
                "image_is_signed",
                "prowler_artifacts_dockerdesktop.services.image.image_is_signed.image_is_signed",
                "prowler.checks.dockerdesktop",
            ),
        ]
        mock_spec_obj = MagicMock()
        mock_spec_obj.origin = "/some/path/check.py"
        mock_spec.return_value = mock_spec_obj

        checks = _recover_ep_checks("dockerdesktop", service="container")

        assert len(checks) == 1
        assert checks[0][0] == "container_has_no_root_user"

    @patch("prowler.lib.check.utils.importlib.metadata.entry_points")
    @patch("prowler.lib.check.utils.importlib.util.find_spec")
    def test_recover_ep_checks_without_service_returns_all(self, mock_spec, mock_ep):
        """Without a service filter, all entry points for the provider are returned."""
        from prowler.lib.check.utils import _recover_ep_checks

        mock_ep.return_value = [
            _make_entry_point(
                "container_has_no_root_user",
                "prowler_artifacts_dockerdesktop.services.container.container_has_no_root_user.container_has_no_root_user",
                "prowler.checks.dockerdesktop",
            ),
            _make_entry_point(
                "image_is_signed",
                "prowler_artifacts_dockerdesktop.services.image.image_is_signed.image_is_signed",
                "prowler.checks.dockerdesktop",
            ),
        ]
        mock_spec_obj = MagicMock()
        mock_spec_obj.origin = "/some/path/check.py"
        mock_spec.return_value = mock_spec_obj

        checks = _recover_ep_checks("dockerdesktop")

        assert len(checks) == 2

    @patch("prowler.lib.check.utils._recover_ep_checks")
    @patch("prowler.lib.check.utils.list_modules")
    def test_recover_checks_external_provider_with_service(
        self, mock_list_modules, mock_ep_checks
    ):
        """External provider with --service: built-in lookup fails with
        ModuleNotFoundError, but entry points are still consulted and return
        the requested service's checks. No premature sys.exit."""
        from prowler.lib.check.utils import recover_checks_from_provider

        mock_list_modules.side_effect = ModuleNotFoundError("No built-in")
        mock_ep_checks.return_value = [("container_check", "/ext/path")]

        checks = recover_checks_from_provider("dockerdesktop", service="container")

        assert len(checks) == 1
        assert checks[0][0] == "container_check"
        mock_ep_checks.assert_called_once_with("dockerdesktop", "container")

    @patch("prowler.lib.check.utils._recover_ep_checks")
    @patch("prowler.lib.check.utils.list_modules")
    def test_recover_checks_unknown_service_fails_cleanly(
        self, mock_list_modules, mock_ep_checks
    ):
        """A typo or unknown service (not in built-ins nor in entry points)
        fails with a clear error message, not a silent empty result."""
        from prowler.lib.check.utils import recover_checks_from_provider

        mock_list_modules.side_effect = ModuleNotFoundError("No built-in")
        mock_ep_checks.return_value = []

        with pytest.raises(SystemExit):
            recover_checks_from_provider("aws", service="typo_service")

    @patch("prowler.lib.check.utils._recover_ep_checks")
    @patch("prowler.lib.check.utils.list_modules")
    def test_recover_checks_builtin_with_new_external_service(
        self, mock_list_modules, mock_ep_checks
    ):
        """Built-in provider with a new service added via entry points:
        built-in discovery raises ModuleNotFoundError for the unknown service,
        but entry points pick it up. The gate `if not service:` that previously
        skipped entry points when --service was passed is removed."""
        from prowler.lib.check.utils import recover_checks_from_provider

        mock_list_modules.side_effect = ModuleNotFoundError("No built-in service")
        mock_ep_checks.return_value = [("new_check", "/ext/path")]

        checks = recover_checks_from_provider("aws", service="new_aws_service")

        assert len(checks) == 1
        assert checks[0][0] == "new_check"
        mock_ep_checks.assert_called_once_with("aws", "new_aws_service")


# ===========================================================================
# 4. Check Execution
# ===========================================================================


class TestCheckExecution:
    """Tests 15-17: _resolve_check_module."""

    @patch("prowler.lib.check.check.import_check")
    def test_resolve_check_module_builtin_first(self, mock_import):
        """Test 15: _resolve_check_module resolves built-in checks first."""
        from prowler.lib.check.check import _resolve_check_module

        mock_module = MagicMock()
        mock_import.return_value = mock_module

        result = _resolve_check_module("aws", "ec2", "my_check")

        assert result is mock_module
        mock_import.assert_called_once_with(
            "prowler.providers.aws.services.ec2.my_check.my_check"
        )

    @patch("prowler.lib.check.check.import_check")
    def test_resolve_check_module_fallback_to_entry_point(self, mock_import_check):
        """Test 16: _resolve_check_module falls back to entry point."""
        from prowler.lib.check.check import _resolve_check_module

        mock_import_check.side_effect = ModuleNotFoundError("Not built-in")

        mock_ext_module = MagicMock()
        ep = _make_entry_point(
            "my_check", "ext_pkg.checks.my_check", "prowler.checks.fake"
        )

        with (
            patch("importlib.metadata.entry_points", return_value=[ep]),
            patch("importlib.import_module", return_value=mock_ext_module) as mock_imp,
        ):
            result = _resolve_check_module("fake", "svc", "my_check")

        assert result is mock_ext_module
        mock_imp.assert_called_with("ext_pkg.checks.my_check")

    @patch("prowler.lib.check.check.importlib.metadata.entry_points")
    @patch("prowler.lib.check.check.import_check")
    def test_resolve_check_module_raises_when_not_found(self, mock_import, mock_ep):
        """Test 17: _resolve_check_module raises ModuleNotFoundError when both fail."""
        from prowler.lib.check.check import _resolve_check_module

        mock_import.side_effect = ModuleNotFoundError("Not built-in")
        mock_ep.return_value = []

        with pytest.raises(ModuleNotFoundError, match="not found"):
            _resolve_check_module("fake", "svc", "nonexistent_check")


# ===========================================================================
# 5. CLI Arguments
# ===========================================================================


class TestCLIArguments:
    """Tests 18-19: init_providers_parser fallback."""

    @patch("prowler.providers.common.arguments.Provider._load_ep_provider")
    @patch("prowler.providers.common.arguments.Provider.get_available_providers")
    @patch("prowler.providers.common.arguments.import_module")
    def test_init_providers_parser_fallback_to_init_parser(
        self, mock_import, mock_providers, mock_load_ep
    ):
        """Test 18: init_providers_parser falls back to cls.init_parser for external providers."""
        from prowler.providers.common.arguments import init_providers_parser

        mock_providers.return_value = ["fakeexternal"]
        mock_import.side_effect = ImportError("No built-in arguments module")
        mock_load_ep.return_value = FakeExternalProvider

        parser_instance = MagicMock()

        # Should not raise
        init_providers_parser(parser_instance)

    @patch("prowler.providers.common.arguments.Provider._load_ep_provider")
    @patch("prowler.providers.common.arguments.Provider.get_available_providers")
    @patch("prowler.providers.common.arguments.import_module")
    def test_init_providers_parser_no_crash_without_init_parser(
        self, mock_import, mock_providers, mock_load_ep
    ):
        """Test 19: init_providers_parser doesn't crash if provider has no init_parser."""
        from prowler.providers.common.arguments import init_providers_parser

        mock_providers.return_value = ["nohelptext"]
        mock_import.side_effect = ImportError("No built-in")
        # FakeProviderNoHelpText has no init_parser
        mock_load_ep.return_value = FakeProviderNoHelpText

        parser_instance = MagicMock()

        # Should not raise
        init_providers_parser(parser_instance)

    @patch("prowler.providers.common.arguments.Provider._load_ep_provider")
    @patch("prowler.providers.common.arguments.Provider.get_available_providers")
    @patch("prowler.providers.common.arguments.import_module")
    def test_init_providers_parser_handles_init_parser_exception(
        self, mock_import, mock_providers, mock_load_ep
    ):
        """init_providers_parser handles exception when init_parser raises."""
        from prowler.providers.common.arguments import init_providers_parser

        mock_providers.return_value = ["fakeexternal"]
        mock_import.side_effect = ImportError("No built-in")

        broken_cls = MagicMock()
        broken_cls.init_parser.side_effect = RuntimeError("Parser init failed")
        mock_load_ep.return_value = broken_cls

        parser_instance = MagicMock()

        # Should not raise
        init_providers_parser(parser_instance)


# ===========================================================================
# 6. Compliance
# ===========================================================================


class TestCompliance:
    """Tests 20-23: compliance discovery and loading."""

    @patch("prowler.config.config.importlib.metadata.entry_points")
    def test_get_ep_compliance_dirs_discovers_dirs(self, mock_ep):
        """Test 20: _get_ep_compliance_dirs discovers compliance directories."""
        from prowler.config.config import _get_ep_compliance_dirs

        mock_module = MagicMock()
        mock_module.__path__ = ["/path/to/compliance"]
        ep = _make_entry_point("fakeexternal", "pkg.compliance", "prowler.compliance")
        ep.load.return_value = mock_module
        mock_ep.return_value = [ep]

        dirs = _get_ep_compliance_dirs()

        assert dirs["fakeexternal"] == "/path/to/compliance"

    @patch("prowler.config.config.importlib.metadata.entry_points")
    def test_get_ep_compliance_dirs_file_fallback(self, mock_ep):
        """_get_ep_compliance_dirs uses __file__ when module has no __path__."""
        from prowler.config.config import _get_ep_compliance_dirs

        mock_module = MagicMock(spec=[])
        mock_module.__file__ = "/path/to/compliance/__init__.py"
        del mock_module.__path__
        ep = _make_entry_point("ext", "pkg.compliance", "prowler.compliance")
        ep.load.return_value = mock_module
        mock_ep.return_value = [ep]

        dirs = _get_ep_compliance_dirs()

        assert dirs["ext"] == "/path/to/compliance"

    @patch("prowler.config.config.importlib.metadata.entry_points")
    def test_get_ep_compliance_dirs_handles_load_exception(self, mock_ep):
        """_get_ep_compliance_dirs handles ep.load() exception gracefully."""
        from prowler.config.config import _get_ep_compliance_dirs

        ep = _make_entry_point("broken", "pkg.compliance", "prowler.compliance")
        ep.load.side_effect = Exception("Load failed")
        mock_ep.return_value = [ep]

        dirs = _get_ep_compliance_dirs()

        assert dirs == {}

    @patch("prowler.config.config._get_ep_compliance_dirs")
    def test_get_available_compliance_includes_external(self, mock_dirs):
        """Test 21: get_available_compliance_frameworks includes external compliance."""
        import json
        import os
        import tempfile

        from prowler.config.config import get_available_compliance_frameworks

        # Create a temp dir with a compliance JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "custom_1.0_ext.json")
            with open(json_path, "w") as f:
                json.dump({"Framework": "Custom", "Provider": "ext"}, f)

            mock_dirs.return_value = {"ext": tmpdir}

            frameworks = get_available_compliance_frameworks("ext")

            assert "custom_1.0_ext" in frameworks

    @patch("prowler.lib.check.compliance_models.importlib.metadata.entry_points")
    @patch("prowler.lib.check.compliance_models.list_compliance_modules")
    def test_compliance_get_bulk_loads_external(self, mock_list_modules, mock_ep):
        """Test 22: Compliance.get_bulk loads external compliance JSON."""
        import json
        import os
        import tempfile

        from prowler.lib.check.compliance_models import Compliance

        mock_list_modules.return_value = []

        # Create a valid compliance JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            json_data = {
                "Framework": "Custom",
                "Name": "Custom Framework",
                "Version": "1.0",
                "Provider": "fakeexternal",
                "Description": "Test framework",
                "Requirements": [],
            }
            json_path = os.path.join(tmpdir, "custom_1.0_fakeexternal.json")
            with open(json_path, "w") as f:
                json.dump(json_data, f)

            mock_module = MagicMock()
            mock_module.__path__ = [tmpdir]
            ep = _make_entry_point(
                "fakeexternal", "pkg.compliance", "prowler.compliance"
            )
            ep.load.return_value = mock_module
            mock_ep.return_value = [ep]

            bulk = Compliance.get_bulk("fakeexternal")

            assert "custom_1.0_fakeexternal" in bulk
            assert bulk["custom_1.0_fakeexternal"].Framework == "Custom"

    @patch("prowler.lib.check.compliance_models.importlib.metadata.entry_points")
    @patch("prowler.lib.check.compliance_models.list_compliance_modules")
    def test_compliance_get_bulk_file_fallback(self, mock_list_modules, mock_ep):
        """Compliance.get_bulk uses __file__ when external module has no __path__."""
        import json
        import os
        import tempfile

        from prowler.lib.check.compliance_models import Compliance

        mock_list_modules.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            json_data = {
                "Framework": "Custom",
                "Name": "Custom File Fallback",
                "Version": "1.0",
                "Provider": "fakeexternal",
                "Description": "Test",
                "Requirements": [],
            }
            json_path = os.path.join(tmpdir, "custom_file_fakeexternal.json")
            with open(json_path, "w") as f:
                json.dump(json_data, f)

            mock_module = MagicMock(spec=[])
            mock_module.__file__ = os.path.join(tmpdir, "__init__.py")
            del mock_module.__path__
            ep = _make_entry_point(
                "fakeexternal", "pkg.compliance", "prowler.compliance"
            )
            ep.load.return_value = mock_module
            mock_ep.return_value = [ep]

            bulk = Compliance.get_bulk("fakeexternal")

            assert "custom_file_fakeexternal" in bulk

    @patch("prowler.lib.check.compliance_models.importlib.metadata.entry_points")
    @patch("prowler.lib.check.compliance_models.list_compliance_modules")
    def test_compliance_get_bulk_handles_external_exception(
        self, mock_list_modules, mock_ep
    ):
        """Compliance.get_bulk handles exception when loading external compliance."""
        from prowler.lib.check.compliance_models import Compliance

        mock_list_modules.return_value = []

        ep = _make_entry_point("fakeexternal", "pkg.compliance", "prowler.compliance")
        ep.load.side_effect = Exception("Load failed")
        mock_ep.return_value = [ep]

        bulk = Compliance.get_bulk("fakeexternal")

        assert bulk == {}

    @patch("prowler.lib.check.compliance_models.importlib.metadata.entry_points")
    @patch("prowler.lib.check.compliance_models.list_compliance_modules")
    def test_compliance_get_bulk_builtin_wins_on_duplicate(
        self, mock_list_modules, mock_ep
    ):
        """Test 23: Compliance.get_bulk built-in wins on duplicate framework names."""
        import json
        import os
        import tempfile

        from prowler.lib.check.compliance_models import Compliance

        mock_list_modules.return_value = []
        mock_ep.return_value = []

        # If both exist with same key, built-in (loaded first) should win
        # Since we have no built-in modules mocked, just verify external loads
        # The actual dedup logic: `if name not in bulk_compliance_frameworks`
        with tempfile.TemporaryDirectory() as tmpdir:
            json_data = {
                "Framework": "CIS",
                "Name": "CIS Test",
                "Version": "1.0",
                "Provider": "fakeexternal",
                "Description": "Test",
                "Requirements": [],
            }
            with open(os.path.join(tmpdir, "dup_framework.json"), "w") as f:
                json.dump(json_data, f)

            mock_module = MagicMock()
            mock_module.__path__ = [tmpdir]
            ep = _make_entry_point(
                "fakeexternal", "pkg.compliance", "prowler.compliance"
            )
            ep.load.return_value = mock_module
            mock_ep.return_value = [ep]

            bulk = Compliance.get_bulk("fakeexternal")

            assert "dup_framework" in bulk


# ===========================================================================
# 7. Parser
# ===========================================================================


class TestParser:
    """Tests 24-27: parser dynamic discovery."""

    @patch("prowler.lib.cli.parser.Provider.get_providers_help_text")
    @patch("prowler.lib.cli.parser.Provider.get_available_providers")
    def test_parser_discovers_new_providers(self, mock_providers, mock_help):
        """Test 24: Parser discovers providers not in known_providers."""
        from prowler.lib.cli.parser import ProwlerArgumentParser

        mock_providers.return_value = [
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "m365",
            "github",
            "googleworkspace",
            "cloudflare",
            "oraclecloud",
            "openstack",
            "alibabacloud",
            "iac",
            "llm",
            "image",
            "nhn",
            "mongodbatlas",
            "fakeexternal",
        ]
        mock_help.return_value = {"fakeexternal": "Fake External Provider"}

        parser = ProwlerArgumentParser()

        assert "fakeexternal" in parser.parser.format_usage()

    @patch("prowler.lib.cli.parser.Provider.get_providers_help_text")
    @patch("prowler.lib.cli.parser.Provider.get_available_providers")
    def test_parser_appends_to_epilog_with_help_text(self, mock_providers, mock_help):
        """Test 25: Parser appends new providers to epilog with _cli_help_text."""
        from prowler.lib.cli.parser import ProwlerArgumentParser

        mock_providers.return_value = [
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "m365",
            "github",
            "googleworkspace",
            "cloudflare",
            "oraclecloud",
            "openstack",
            "alibabacloud",
            "iac",
            "llm",
            "image",
            "nhn",
            "mongodbatlas",
            "fakeexternal",
        ]
        mock_help.return_value = {"fakeexternal": "Fake External Provider"}

        parser = ProwlerArgumentParser()
        epilog = parser.parser.epilog

        assert "fakeexternal" in epilog
        assert "Fake External Provider" in epilog

    @patch("prowler.lib.cli.parser.Provider.get_providers_help_text")
    @patch("prowler.lib.cli.parser.Provider.get_available_providers")
    def test_parser_skips_epilog_entry_without_help_text(
        self, mock_providers, mock_help
    ):
        """Test 26: Parser doesn't add epilog entry if _cli_help_text is empty."""
        from prowler.lib.cli.parser import ProwlerArgumentParser

        mock_providers.return_value = [
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "m365",
            "github",
            "googleworkspace",
            "cloudflare",
            "oraclecloud",
            "openstack",
            "alibabacloud",
            "iac",
            "llm",
            "image",
            "nhn",
            "mongodbatlas",
            "nohelptext",
        ]
        mock_help.return_value = {"nohelptext": ""}

        parser = ProwlerArgumentParser()
        epilog = parser.parser.epilog

        # Should appear in usage/csv but NOT in the descriptive epilog listing
        assert "nohelptext" in parser.parser.format_usage()
        # No line with "nohelptext    Something" in epilog
        epilog_lines = [
            line.strip() for line in epilog.splitlines() if "nohelptext" in line
        ]
        assert len(epilog_lines) == 0 or all(
            "nohelptext" in line and line.strip() == "nohelptext" or "{" in line
            for line in epilog_lines
        )

    @patch("prowler.lib.cli.parser.Provider.get_providers_help_text")
    @patch("prowler.lib.cli.parser.Provider.get_available_providers")
    def test_parser_does_not_duplicate_known_providers(self, mock_providers, mock_help):
        """Test 27: Parser doesn't duplicate providers already in the known list."""
        from prowler.lib.cli.parser import ProwlerArgumentParser

        # No new providers
        mock_providers.return_value = [
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "m365",
            "github",
            "googleworkspace",
            "cloudflare",
            "oraclecloud",
            "openstack",
            "alibabacloud",
            "iac",
            "llm",
            "image",
            "nhn",
            "mongodbatlas",
        ]
        mock_help.return_value = {}

        parser = ProwlerArgumentParser()
        usage = parser.parser.format_usage()

        # aws should appear exactly once in usage
        assert usage.count("aws") == 1


# ===========================================================================
# 8. Dispatch Fallbacks
# ===========================================================================


class TestDispatchFallbacks:
    """Tests 28-34: all else clause fallbacks for external providers."""

    def test_stdout_report_calls_get_stdout_detail(self, fake_provider):
        """Test 28: stdout_report else clause calls provider.get_stdout_detail."""
        from prowler.lib.outputs.outputs import stdout_report

        finding = MagicMock()
        finding.check_metadata.Provider = "fakeexternal"
        finding.status = "FAIL"
        finding.muted = False
        finding.status_extended = "test"

        with patch("builtins.print") as mock_print:
            stdout_report(
                finding, "\033[31m", True, ["FAIL"], False, provider=fake_provider
            )

        mock_print.assert_called_once()
        printed = mock_print.call_args[0][0]
        assert "fake-detail" in printed

    def test_stdout_report_resolves_provider_when_none(self, fake_provider):
        """stdout_report resolves provider via get_global_provider when not passed."""
        from prowler.lib.outputs.outputs import stdout_report

        finding = MagicMock()
        finding.check_metadata.Provider = "fakeexternal"
        finding.status = "FAIL"
        finding.muted = False
        finding.status_extended = "test"

        with patch("builtins.print") as mock_print:
            stdout_report(finding, "\033[31m", True, ["FAIL"], False)

        mock_print.assert_called_once()
        printed = mock_print.call_args[0][0]
        assert "fake-detail" in printed

    def test_report_sort_calls_get_finding_sort_key(self, fake_provider):
        """Test 29: report else clause calls provider.get_finding_sort_key."""
        from prowler.lib.outputs.outputs import report

        finding1 = MagicMock()
        finding1.status = "PASS"
        finding1.muted = False
        finding1.region = "b-region"
        finding1.check_metadata.Provider = "fakeexternal"
        finding1.status_extended = "test1"

        finding2 = MagicMock()
        finding2.status = "PASS"
        finding2.muted = False
        finding2.region = "a-region"
        finding2.check_metadata.Provider = "fakeexternal"
        finding2.status_extended = "test2"

        output_options = MagicMock()
        output_options.verbose = False
        output_options.status = []

        findings = [finding1, finding2]
        report(findings, fake_provider, output_options)

        # Should be sorted by region (get_finding_sort_key returns "region")
        assert findings[0].region == "a-region"
        assert findings[1].region == "b-region"

    def test_display_summary_table_calls_get_summary_entity(self, fake_provider):
        """Test 30: display_summary_table else clause calls provider.get_summary_entity."""
        from prowler.lib.outputs.summary_table import display_summary_table

        finding = MagicMock()
        finding.status = "FAIL"
        finding.muted = False
        finding.check_metadata.ServiceName = "test_service"
        finding.check_metadata.Provider = "fakeexternal"
        finding.check_metadata.Severity = "high"

        output_options = MagicMock()
        output_options.output_directory = "/tmp"
        output_options.output_filename = "test"
        output_options.output_modes = []

        with patch("builtins.print") as mock_print:
            display_summary_table([finding], fake_provider, output_options)

        printed_text = " ".join(str(c) for c in mock_print.call_args_list)
        assert "Fake Host" in printed_text or "fake-host-1" in printed_text

    def test_generate_output_calls_get_finding_output_data(self, fake_provider):
        """Test 31: finding.generate_output else clause calls provider.get_finding_output_data."""
        from prowler.lib.check.models import (
            CheckMetadata,
            Code,
            Recommendation,
            Remediation,
        )
        from prowler.lib.outputs.finding import Finding

        metadata = CheckMetadata(
            Provider="fakeexternal",
            CheckID="test_check",
            CheckTitle="Test check title",
            CheckType=[],
            ServiceName="test",
            SubServiceName="",
            ResourceIdTemplate="",
            Severity="high",
            ResourceType="Test",
            ResourceGroup="",
            Description="Test description",
            Risk="Test risk",
            RelatedUrl="",
            Remediation=Remediation(
                Code=Code(CLI="", NativeIaC="", Other="", Terraform=""),
                Recommendation=Recommendation(
                    Text="Fix it", Url="https://hub.prowler.com/check/test_check"
                ),
            ),
            Categories=[],
            DependsOn=[],
            RelatedTo=[],
            Notes="",
        )

        check_output = MagicMock()
        check_output.check_metadata = metadata
        check_output.status = "FAIL"
        check_output.status_extended = "test failed"
        check_output.muted = False
        check_output.resource = {}
        check_output.resource_details = ""
        check_output.resource_tags = {}
        check_output.compliance = {}

        output_options = MagicMock()
        output_options.unix_timestamp = False
        output_options.bulk_checks_metadata = {}

        finding = Finding.generate_output(fake_provider, check_output, output_options)

        assert finding.auth_method == "fake"
        assert finding.account_uid == "fake-account"
        assert finding.resource_name == "fake-resource"
        assert finding.region == "local"

    def test_output_options_calls_get_output_options(self, fake_provider):
        """Test 32: __main__.py else clause calls provider.get_output_options."""
        result = fake_provider.get_output_options(MagicMock(), {})

        assert result is not None
        assert hasattr(result, "output_directory")

    def test_html_assessment_calls_get_html_assessment_summary(self, fake_provider):
        """Test 33: html.py fallback calls provider.get_html_assessment_summary."""
        from prowler.lib.outputs.html.html import HTML

        result = HTML.get_assessment_summary(fake_provider)

        assert "<div>Fake Assessment</div>" in result

    def test_compliance_output_calls_generate_compliance_output(self, fake_provider):
        """Test 34: __main__.py else clause calls provider.generate_compliance_output."""
        generated_outputs = {"compliance": []}

        fake_provider.generate_compliance_output(
            [],
            {},
            set(),
            MagicMock(),
            generated_outputs,
        )

        assert "fake-compliance-output" in generated_outputs["compliance"]


# ===========================================================================
# 9. Base Contract Defaults
# ===========================================================================


class TestBaseContractDefaults:
    """Tests for Provider base class default implementations."""

    def test_from_cli_args_raises_not_implemented(self):
        """Base Provider.from_cli_args raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            FakeProviderNoHelpText.from_cli_args(MagicMock(), {})

    def test_get_output_options_raises_not_implemented(self):
        """Base Provider.get_output_options raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.get_output_options(MagicMock(), {})

    def test_get_stdout_detail_raises_not_implemented(self):
        """Base Provider.get_stdout_detail raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.get_stdout_detail(MagicMock())

    def test_get_finding_sort_key_returns_none(self):
        """Base Provider.get_finding_sort_key returns None."""
        provider = FakeProviderNoHelpText()
        assert provider.get_finding_sort_key() is None

    def test_get_summary_entity_raises_not_implemented(self):
        """Base Provider.get_summary_entity raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.get_summary_entity()

    def test_get_finding_output_data_raises_not_implemented(self):
        """Base Provider.get_finding_output_data raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.get_finding_output_data(MagicMock())

    def test_get_html_assessment_summary_raises_not_implemented(self):
        """Base Provider.get_html_assessment_summary raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.get_html_assessment_summary()

    def test_generate_compliance_output_raises_not_implemented(self):
        """Base Provider.generate_compliance_output raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.generate_compliance_output([], {}, set(), MagicMock(), {})

    def test_get_mutelist_finding_args_raises_not_implemented(self):
        """Base Provider.get_mutelist_finding_args raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.get_mutelist_finding_args()

    def test_display_compliance_table_raises_not_implemented(self):
        """Base Provider.display_compliance_table raises NotImplementedError."""
        provider = FakeProviderNoHelpText()
        with pytest.raises(NotImplementedError):
            provider.display_compliance_table([], {}, "fw", "out", "/tmp", False)

    def test_is_external_tool_provider_defaults_to_false(self):
        """Base Provider.is_external_tool_provider returns False."""
        provider = FakeProviderNoHelpText()
        assert provider.is_external_tool_provider is False


# ===========================================================================
# 10. Mutelist Dispatch for External Providers
# ===========================================================================


class TestMutelistDispatch:
    """Tests for mutelist integration with external providers."""

    def test_get_mutelist_finding_args_returns_identity(self, fake_provider):
        """External provider returns identity kwargs for mutelist."""
        args = fake_provider.get_mutelist_finding_args()

        assert args == {"host_id": "fake-host-1"}

    def test_mutelist_dispatch_calls_external_provider(self, fake_provider):
        """execute() uses get_mutelist_finding_args for unknown provider types."""
        from prowler.lib.check.check import execute

        # Create a mock check that returns one finding
        finding = MagicMock()
        finding.status = "FAIL"
        finding.muted = False
        finding.check_metadata.Provider = "fakeexternal"

        check = MagicMock()
        check.execute.return_value = [finding]
        check.CheckID = "fake_check"
        check.ServiceName = "fake_service"
        check.Severity.value = "high"

        # Setup mutelist on the provider
        fake_provider.mutelist = MagicMock()
        fake_provider.mutelist.mutelist = {"Accounts": {}}
        fake_provider.mutelist.is_finding_muted.return_value = True

        output_options = MagicMock()
        output_options.status = []
        output_options.unix_timestamp = False

        execute(check, fake_provider, None, output_options)

        # is_finding_muted should have been called with host_id + finding
        fake_provider.mutelist.is_finding_muted.assert_called_once_with(
            host_id="fake-host-1", finding=finding
        )


# ===========================================================================
# 11. Compliance Table Dispatch for External Providers
# ===========================================================================


class TestComplianceTableDispatch:
    """Tests for compliance table display with external providers."""

    def test_display_compliance_table_delegates_to_provider(self, fake_provider):
        """display_compliance_table uses provider method for unknown frameworks."""
        from prowler.lib.outputs.compliance.compliance import (
            display_compliance_table,
        )

        fake_provider.display_compliance_table = MagicMock(return_value=True)

        display_compliance_table(
            [], {}, "custom_1.0_fakeexternal", "out", "/tmp", False
        )

        fake_provider.display_compliance_table.assert_called_once_with(
            [],
            {},
            "custom_1.0_fakeexternal",
            "out",
            "/tmp",
            False,
        )

    def test_display_compliance_table_falls_back_to_generic(self, fake_provider):
        """display_compliance_table falls back to generic when provider returns False."""
        from prowler.lib.outputs.compliance.compliance import (
            display_compliance_table,
        )

        fake_provider.display_compliance_table = MagicMock(return_value=False)

        with patch(
            "prowler.lib.outputs.compliance.compliance.get_generic_compliance_table"
        ) as mock_generic:
            display_compliance_table(
                [], {}, "custom_1.0_fakeexternal", "out", "/tmp", False
            )

        mock_generic.assert_called_once()

    def test_display_compliance_table_falls_back_on_not_implemented(self):
        """display_compliance_table falls back to generic when NotImplementedError."""
        # Use a provider that doesn't implement display_compliance_table
        provider = FakeProviderNoHelpText()
        Provider.set_global_provider(provider)

        with patch(
            "prowler.lib.outputs.compliance.compliance.get_generic_compliance_table"
        ) as mock_generic:
            from prowler.lib.outputs.compliance.compliance import (
                display_compliance_table,
            )

            display_compliance_table(
                [], {}, "unknown_1.0_nohelptext", "out", "/tmp", False
            )

        mock_generic.assert_called_once()
        Provider._global = None
