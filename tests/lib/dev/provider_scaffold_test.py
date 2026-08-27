import importlib
import pkgutil
import re
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from prowler.lib.dev.provider_scaffold import (
    AUTH_MODES,
    KINDS,
    ProviderSpec,
    ScaffoldError,
    build_builtin_plan,
    build_external_plan,
    build_plan,
    existing_builtin_names,
    find_repo_root,
    next_exception_code_range,
    validate_name,
    write_plan,
)
from prowler.providers.common.provider import Provider

REPO_ROOT = Path(__file__).resolve().parents[3]


def builtin_spec(**overrides) -> ProviderSpec:
    defaults = {
        "name": "acmecloud",
        "kind": "api",
        "scope": "builtin",
        "auth": "env",
        "regional": False,
    }
    defaults.update(overrides)
    return ProviderSpec(**defaults)


def discovered_builtin_names() -> set:
    """Enumerate built-in providers the way get_available_providers() does.

    Provider.get_available_providers() cannot be called from here in a full
    test run. tests/lib/cli/parser_test.py starts a patch over it in
    setup_method with no matching teardown, so its hardcoded 19-provider list
    leaks into every test that runs afterwards. This walks
    prowler.providers.__path__ with pkgutil.iter_modules, which is what the
    real implementation does.
    """
    providers_package = importlib.import_module("prowler.providers")
    return {
        name
        for _, name, is_package in pkgutil.iter_modules(providers_package.__path__)
        if is_package and name != "common"
    }


class Test_validate_name:
    @pytest.mark.parametrize(
        "name",
        ["acme_cloud", "acme-cloud", "acmeCloud", "AcmeCloud", "1acme", "acme.cloud"],
    )
    def test_rejects_names_discovery_cannot_resolve(self, name):
        """Provider.get_class() derives the class name with str.capitalize().

        `acme_cloud`.capitalize() is `Acme_cloud`, so a provider named that way
        would have to define Acme_cloudProvider to be found. Rejecting the name
        up front is cheaper than a provider that silently fails to load.
        """
        with pytest.raises(ScaffoldError):
            validate_name(name)

    def test_rejects_an_empty_name(self):
        with pytest.raises(ScaffoldError):
            validate_name("")

    @pytest.mark.parametrize("name", ["aws", "acmecloud", "googleworkspace", "m365"])
    def test_accepts_the_shapes_real_providers_use(self, name):
        assert validate_name(name) == name


class Test_ProviderSpec:
    def test_class_prefix_matches_what_get_class_looks_up(self):
        """A multi-word name gets one capital, matching str.capitalize()."""
        assert builtin_spec(name="googleworkspace").class_prefix == "Googleworkspace"

    def test_env_prefix(self):
        assert builtin_spec(name="acmecloud").env_prefix == "ACMECLOUD"

    def test_full_stack_is_not_sdk_only(self):
        """Only a provider with sdk_only False is listed by the API and UI."""
        assert builtin_spec(scope="full-stack").sdk_only is False

    def test_builtin_and_external_are_sdk_only(self):
        assert builtin_spec(scope="builtin").sdk_only is True
        assert builtin_spec(scope="external").sdk_only is True

    @pytest.mark.parametrize("kind", ["sdk", "api", "hybrid"])
    def test_kinds_that_audit_an_api_need_services(self, kind):
        assert builtin_spec(kind=kind).needs_services is True

    def test_tool_kind_needs_no_services(self):
        """iac, image and llm ship with no services/ at all."""
        assert builtin_spec(kind="tool").needs_services is False


class Test_build_builtin_plan:
    @pytest.mark.parametrize("kind", KINDS)
    def test_always_generates_the_arguments_module(self, kind):
        """lib/arguments/arguments.py is required for every built-in provider.

        prowler/providers/common/arguments.py imports it for every built-in and
        calls init_parser on it, and a failure there exits the CLI when that
        provider is the one invoked. All 23 current providers have it.
        """
        plan = build_builtin_plan(builtin_spec(kind=kind), REPO_ROOT)

        assert "prowler/providers/acmecloud/lib/arguments/arguments.py" in plan.files
        assert (
            "def init_parser(self):"
            in plan.files["prowler/providers/acmecloud/lib/arguments/arguments.py"]
        )

    @pytest.mark.parametrize("kind", KINDS)
    def test_always_generates_the_files_discovery_depends_on(self, kind):
        plan = build_builtin_plan(builtin_spec(kind=kind), REPO_ROOT)

        for required in [
            "prowler/providers/acmecloud/__init__.py",
            "prowler/providers/acmecloud/acmecloud_provider.py",
            "prowler/providers/acmecloud/models.py",
        ]:
            assert required in plan.files

    def test_generates_the_class_name_discovery_looks_up(self):
        plan = build_builtin_plan(builtin_spec(), REPO_ROOT)

        source = plan.files["prowler/providers/acmecloud/acmecloud_provider.py"]
        assert "class AcmecloudProvider(Provider):" in source

    def test_api_kind_gets_a_service_layer(self):
        plan = build_builtin_plan(builtin_spec(kind="api"), REPO_ROOT)

        assert "prowler/providers/acmecloud/lib/service/service.py" in plan.files
        assert "prowler/providers/acmecloud/services/__init__.py" in plan.files

    def test_tool_kind_gets_no_service_layer(self):
        plan = build_builtin_plan(builtin_spec(kind="tool"), REPO_ROOT)

        assert "prowler/providers/acmecloud/lib/service/service.py" not in plan.files
        assert "prowler/providers/acmecloud/services/__init__.py" not in plan.files

    def test_full_stack_declares_application_exposure(self):
        plan = build_builtin_plan(builtin_spec(scope="full-stack"), REPO_ROOT)

        source = plan.files["prowler/providers/acmecloud/acmecloud_provider.py"]
        assert "sdk_only: bool = False" in source

    def test_builtin_leaves_sdk_only_at_its_default(self):
        """The base Provider already defaults sdk_only to True."""
        plan = build_builtin_plan(builtin_spec(scope="builtin"), REPO_ROOT)

        source = plan.files["prowler/providers/acmecloud/acmecloud_provider.py"]
        assert "sdk_only" not in source

    def test_regional_adds_the_region_argument_and_filter(self):
        plan = build_builtin_plan(builtin_spec(regional=True), REPO_ROOT)

        arguments = plan.files["prowler/providers/acmecloud/lib/arguments/arguments.py"]
        provider = plan.files["prowler/providers/acmecloud/acmecloud_provider.py"]
        assert '"--region",' in arguments
        assert "def regions(self):" in provider

    def test_non_regional_adds_neither(self):
        plan = build_builtin_plan(builtin_spec(regional=False), REPO_ROOT)

        arguments = plan.files["prowler/providers/acmecloud/lib/arguments/arguments.py"]
        provider = plan.files["prowler/providers/acmecloud/acmecloud_provider.py"]
        assert '"--region",' not in arguments
        assert "def regions(self):" not in provider

    def test_token_auth_marks_the_flag_as_sensitive(self):
        """The prowler-provider skill requires secret-bearing flags to be
        listed in SENSITIVE_ARGUMENTS so their values are redacted."""
        plan = build_builtin_plan(builtin_spec(auth="token"), REPO_ROOT)

        arguments = plan.files["prowler/providers/acmecloud/lib/arguments/arguments.py"]
        assert 'SENSITIVE_ARGUMENTS = frozenset({"--acmecloud-token"})' in arguments
        assert 'metavar="ACMECLOUD_TOKEN"' in arguments

    def test_env_auth_adds_no_credential_flag(self):
        plan = build_builtin_plan(builtin_spec(auth="env"), REPO_ROOT)

        arguments = plan.files["prowler/providers/acmecloud/lib/arguments/arguments.py"]
        assert "add_argument" not in arguments

    def test_generated_tests_carry_no_init_files(self):
        """scripts/check_test_init_files.py fails the build on any
        __init__.py under tests/."""
        plan = build_builtin_plan(builtin_spec(), REPO_ROOT)

        assert not [
            path
            for path in plan.paths
            if path.startswith("tests/") and path.endswith("__init__.py")
        ]

    def test_generates_tests_for_the_provider_and_its_arguments(self):
        plan = build_builtin_plan(builtin_spec(), REPO_ROOT)

        assert "tests/providers/acmecloud/acmecloud_provider_test.py" in plan.files
        assert "tests/providers/acmecloud/acmecloud_fixtures.py" in plan.files
        assert (
            "tests/providers/acmecloud/lib/arguments/acmecloud_arguments_test.py"
            in plan.files
        )

    def test_reports_the_shared_registrations_it_does_not_patch(self):
        """The dispatch chain, the check report class and the exception code
        block live in files shared by every provider, so they are reported
        rather than edited."""
        plan = build_builtin_plan(builtin_spec(auth="token"), REPO_ROOT)
        steps = "\n".join(plan.next_steps)

        assert "init_global_provider()" in steps
        assert 'elif arguments.provider == "acmecloud":' in steps
        assert "CheckReportAcmecloud" in steps
        assert "prowler/lib/check/models.py" in steps
        assert "changelog.d" in steps

    def test_the_reported_dispatch_snippet_passes_the_auth_argument(self):
        plan = build_builtin_plan(builtin_spec(auth="token", regional=True), REPO_ROOT)
        steps = "\n".join(plan.next_steps)

        assert 'token=getattr(arguments, "acmecloud_token", None)' in steps
        assert 'regions=getattr(arguments, "region", None)' in steps


class Test_build_external_plan:
    def test_declares_the_entry_point_prowler_discovers(self, tmp_path):
        plan = build_external_plan(builtin_spec(scope="external"), tmp_path)

        pyproject = plan.files["pyproject.toml"]
        assert '[project.entry-points."prowler.providers"]' in pyproject
        assert (
            'acmecloud = "prowler_provider_acmecloud.provider:AcmecloudProvider"'
            in pyproject
        )

    def test_implements_both_halves_of_the_external_cli_contract(self, tmp_path):
        """An external provider cannot join the built-in dispatch chain, so it
        needs init_parser for its subparser and from_cli_args for its
        instantiation. No built-in provider implements either."""
        plan = build_external_plan(builtin_spec(scope="external"), tmp_path)

        source = plan.files["prowler_provider_acmecloud/provider.py"]
        assert "def init_parser(self):" in source
        assert (
            "def from_cli_args(cls, arguments: Namespace, fixer_config: dict)" in source
        )

    def test_writes_outside_the_prowler_tree(self, tmp_path):
        plan = build_external_plan(builtin_spec(scope="external"), tmp_path)

        assert not [path for path in plan.paths if path.startswith("prowler/providers")]


class Test_build_plan:
    def test_rejects_a_name_that_already_exists(self):
        with pytest.raises(ScaffoldError, match="already exists"):
            build_plan(builtin_spec(name="aws"), REPO_ROOT)

    def test_rejects_an_invalid_kind(self):
        with pytest.raises(ScaffoldError, match="Invalid kind"):
            build_plan(
                ProviderSpec(name="acmecloud", kind="serverless", scope="builtin"),
                REPO_ROOT,
            )

    def test_rejects_an_invalid_scope(self):
        with pytest.raises(ScaffoldError, match="Invalid scope"):
            build_plan(
                ProviderSpec(name="acmecloud", kind="api", scope="everything"),
                REPO_ROOT,
            )

    def test_rejects_an_invalid_auth_mode(self):
        with pytest.raises(ScaffoldError, match="Invalid auth mode"):
            build_plan(
                ProviderSpec(
                    name="acmecloud", kind="api", scope="builtin", auth="telepathy"
                ),
                REPO_ROOT,
            )

    def test_rejects_a_path_that_is_not_a_prowler_checkout(self, tmp_path):
        with pytest.raises(ScaffoldError, match="does not look like a Prowler"):
            build_plan(builtin_spec(), tmp_path)

    def test_writes_nothing_until_write_plan_is_called(self, tmp_path):
        plan = build_plan(builtin_spec(scope="external"), tmp_path / "out")

        assert plan.files
        assert not (tmp_path / "out").exists()


class Test_write_plan:
    def test_writes_every_planned_file(self, tmp_path):
        plan = build_external_plan(builtin_spec(scope="external"), tmp_path)

        written = write_plan(plan)

        assert len(written) == len(plan.files)
        for path in written:
            assert path.is_file()

    def test_refuses_to_overwrite_by_default(self, tmp_path):
        plan = build_external_plan(builtin_spec(scope="external"), tmp_path)
        write_plan(plan)

        with pytest.raises(ScaffoldError, match="Refusing to overwrite"):
            write_plan(plan)

    def test_force_overwrites(self, tmp_path):
        plan = build_external_plan(builtin_spec(scope="external"), tmp_path)
        write_plan(plan)
        target = tmp_path / "README.md"
        target.write_text("edited")

        write_plan(plan, force=True)

        assert target.read_text() != "edited"


class Test_repo_inspection:
    def test_find_repo_root_walks_up_to_the_checkout(self):
        assert find_repo_root(Path(__file__).parent) == REPO_ROOT

    def test_find_repo_root_raises_outside_a_checkout(self, tmp_path):
        with pytest.raises(ScaffoldError, match="No Prowler repository found"):
            find_repo_root(tmp_path)

    def test_existing_builtin_names_matches_discovery(self):
        """The scaffold reads the tree to decide whether a name is taken, so
        that view has to agree with the one discovery enumerates."""
        assert set(existing_builtin_names(REPO_ROOT)) == discovered_builtin_names()

    def test_every_discovered_provider_is_a_builtin(self):
        for name in discovered_builtin_names():
            assert Provider.is_builtin(name)

    def test_next_exception_code_range_is_above_every_code_in_use(self):
        start, end = next_exception_code_range(REPO_ROOT)

        assert end == start + 99
        highest = 0
        for path in (REPO_ROOT / "prowler" / "providers").glob(
            "*/exceptions/exceptions.py"
        ):
            for match in re.finditer(r"\((\d{4,6}),", path.read_text()):
                highest = max(highest, int(match.group(1)))
        assert start > highest


class Test_generated_code_quality:
    """Generated code lands in a contributor's tree, where Prowler's own CI
    runs black and flake8 over it. A scaffold whose output fails those gates
    hands the contributor a broken first push."""

    SPECS = [
        builtin_spec(kind=kind, scope=scope, auth=auth, regional=regional)
        for kind in ("api", "tool")
        for scope in ("builtin", "full-stack", "external")
        for auth in AUTH_MODES
        for regional in (True, False)
    ]

    @pytest.mark.parametrize(
        "spec", SPECS, ids=lambda s: f"{s.kind}-{s.scope}-{s.auth}-{s.regional}"
    )
    def test_generated_python_is_syntactically_valid(self, spec, tmp_path):
        plan = (
            build_external_plan(spec, tmp_path)
            if spec.scope == "external"
            else build_builtin_plan(spec, REPO_ROOT)
        )

        for relative, source in plan.files.items():
            if relative.endswith(".py"):
                compile(source, relative, "exec")

    @pytest.mark.parametrize(
        "spec", SPECS, ids=lambda s: f"{s.kind}-{s.scope}-{s.auth}-{s.regional}"
    )
    def test_generated_python_is_black_clean(self, spec, tmp_path):
        black = pytest.importorskip("black")
        plan = (
            build_external_plan(spec, tmp_path)
            if spec.scope == "external"
            else build_builtin_plan(spec, REPO_ROOT)
        )

        for relative, source in plan.files.items():
            if relative.endswith(".py") and source:
                assert source == black.format_str(
                    source, mode=black.Mode()
                ), f"{relative} is not black-clean"

    IN_REPO_SPECS = [spec for spec in SPECS if spec.scope != "external"]

    @pytest.mark.parametrize(
        "spec",
        IN_REPO_SPECS,
        ids=lambda s: f"{s.kind}-{s.scope}-{s.auth}-{s.regional}",
    )
    def test_generated_python_is_import_sorted(self, spec):
        """Whether a provider's own imports sort before or after
        prowler.providers.common depends on its name, so the templates cannot
        hardcode the order. External packages are excluded: they live outside
        this repository and isort never runs on them here.
        """
        isort = pytest.importorskip("isort")
        plan = build_builtin_plan(spec, REPO_ROOT)

        for relative, source in plan.files.items():
            if relative.endswith(".py") and source:
                assert source == isort.code(
                    source, profile="black"
                ), f"{relative} is not import-sorted"

    @pytest.mark.parametrize("name", ["acloud", "zcloud", "m365x"])
    def test_import_order_holds_either_side_of_common(self, name):
        """A name sorting before `common` and one sorting after it both have to
        come out ordered."""
        isort = pytest.importorskip("isort")
        plan = build_builtin_plan(builtin_spec(name=name, auth="token"), REPO_ROOT)

        provider = plan.files[f"prowler/providers/{name}/{name}_provider.py"]
        assert provider == isort.code(provider, profile="black")


class Test_generated_provider_is_loadable:
    """The point of the scaffold is a provider Prowler can find and import.

    Rather than writing into prowler/providers/, these tests extend
    prowler.providers.__path__ with a temporary directory. Discovery iterates
    that same __path__ (pkgutil.iter_modules in get_available_providers) and
    get_class imports through it, so this exercises the real code path.
    """

    @staticmethod
    @contextmanager
    def scaffolded(spec, tmp_path):
        """Write a plan to tmp_path and make it importable as a built-in.

        prowler.providers is a namespace package, so its __path__ is a
        _NamespacePath, which supports append but not remove. Swapping in a
        plain list and restoring the original object afterwards leaves the
        interpreter exactly as it was found.
        """
        plan = build_builtin_plan(spec, REPO_ROOT)
        plan.root = tmp_path
        write_plan(plan)

        providers_package = importlib.import_module("prowler.providers")
        original_path = providers_package.__path__
        providers_package.__path__ = list(original_path) + [
            str(tmp_path / "prowler" / "providers")
        ]
        try:
            yield plan
        finally:
            providers_package.__path__ = original_path
            for module in [
                name
                for name in sys.modules
                if name.startswith(f"prowler.providers.{spec.name}")
            ]:
                del sys.modules[module]
            Provider._ep_providers.pop(spec.name, None)

    @pytest.mark.parametrize("scope", ["builtin", "full-stack"])
    def test_generated_provider_is_discovered_and_imports(self, scope, tmp_path):
        name = f"scaffolded{scope.replace('-', '')}"
        spec = builtin_spec(name=name, scope=scope, auth="token", regional=True)

        with self.scaffolded(spec, tmp_path):
            # Layer one: the name is enumerated. Layer two: the module imports
            # and the class lookup resolves.
            assert name in discovered_builtin_names()

            provider_class = Provider.get_class(name)

            assert provider_class.__name__ == f"{name.capitalize()}Provider"
            assert issubclass(provider_class, Provider)
            assert provider_class.sdk_only is (scope != "full-stack")
            assert provider_class._cli_help_text

    def test_generated_arguments_module_builds_a_subparser(self, tmp_path):
        """init_providers_parser() imports lib.arguments.arguments for every
        built-in and calls init_parser on it."""
        name = "scaffoldedargs"
        spec = builtin_spec(name=name, auth="token", regional=True)

        with self.scaffolded(spec, tmp_path):
            module = importlib.import_module(
                f"prowler.providers.{name}.lib.arguments.arguments"
            )

            assert callable(module.init_parser)
            assert module.SENSITIVE_ARGUMENTS == frozenset({f"--{name}-token"})
