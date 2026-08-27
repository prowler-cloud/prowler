"""Generate the minimum consistent structure for a new Prowler provider.

The scaffold writes the files a provider needs in order to be discovered and
loaded, and stops there. Authentication behavior, API semantics and security
checks are left as explicit ``TODO`` markers, because those are decisions no
template can make.

Three registrations live in files shared by every provider, so the scaffold
reports them as next steps with a ready-to-paste snippet instead of patching
them. Editing a shared file by code generation produces a diff no reviewer
wants to read, and a merge conflict for whoever runs the command next.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from prowler.lib.dev import templates

KINDS = ("sdk", "api", "tool", "hybrid")
SCOPES = ("builtin", "external", "full-stack")
AUTH_MODES = ("env", "token", "key-file", "browser")

# Kinds that audit a live API need a service layer. A tool/wrapper provider
# shells out to another binary instead, which is why `iac`, `image` and `llm`
# ship with no `services/` or `lib/service/` at all.
KINDS_WITH_SERVICES = ("sdk", "api", "hybrid")

NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*$")

# Provider.get_class() derives the class name with str.capitalize(), so the
# scaffold refuses any name that would produce a class the loader cannot find.
NAME_HELP = (
    "A provider name must be lowercase letters and digits, starting with a "
    "letter, with no underscores, hyphens or dots. Provider.get_class() builds "
    "the class name with str.capitalize(), so `googleworkspace` resolves to "
    "GoogleworkspaceProvider and a name like `acme_cloud` or `acmeCloud` "
    "cannot be discovered."
)

# Each provider owns a block of 100 exception codes. The scaffold suggests the
# next free block rather than reusing one.
EXCEPTION_CODE_BLOCK = 100
EXCEPTION_CODE_FLOOR = 18000


class ScaffoldError(Exception):
    """Raised when the requested provider cannot be scaffolded."""


@dataclass(frozen=True)
class ProviderSpec:
    """The explicit inputs the generated structure is derived from."""

    name: str
    kind: str
    scope: str
    auth: str = "env"
    regional: bool = False

    @property
    def class_prefix(self) -> str:
        """The class-name prefix the provider loader will look for."""
        return self.name.capitalize()

    @property
    def env_prefix(self) -> str:
        """The prefix used for this provider's environment variables."""
        return self.name.upper()

    @property
    def needs_services(self) -> bool:
        return self.kind in KINDS_WITH_SERVICES

    @property
    def sdk_only(self) -> bool:
        """Whether the API and UI list this provider.

        `sdk_only` defaults to True on the base Provider, and only a provider
        that sets it to False appears in Provider.get_app_providers(), which is
        what the application enumerates.
        """
        return self.scope != "full-stack"


@dataclass
class ScaffoldPlan:
    """The files a run would write, plus what is left for the contributor."""

    root: Path
    files: Dict[str, str] = field(default_factory=dict)
    next_steps: List[str] = field(default_factory=list)

    @property
    def paths(self) -> List[str]:
        return sorted(self.files)


def validate_name(name: str) -> str:
    """Check a provider name against the discovery contract.

    Args:
        name: The requested provider name.

    Returns:
        The validated name.

    Raises:
        ScaffoldError: If the name cannot be discovered by Prowler.
    """
    if not name:
        raise ScaffoldError(f"A provider name is required. {NAME_HELP}")
    if not NAME_PATTERN.match(name):
        raise ScaffoldError(f"Invalid provider name '{name}'. {NAME_HELP}")
    return name


def find_repo_root(start: Optional[Path] = None) -> Path:
    """Locate the Prowler repository root by walking up from ``start``.

    Args:
        start: Directory to start from. Defaults to the current directory.

    Returns:
        The repository root.

    Raises:
        ScaffoldError: If no Prowler checkout is found.
    """
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "prowler" / "providers" / "common" / "provider.py").is_file():
            return candidate
    raise ScaffoldError(
        "No Prowler repository found. Run this from a Prowler checkout, or "
        "pass --path pointing at one. To scaffold a provider that lives "
        "outside this repository, use --scope external instead."
    )


def existing_builtin_names(repo_root: Path) -> List[str]:
    """List the built-in provider directory names in a checkout.

    This reads the directory tree rather than calling
    Provider.get_available_providers() so that it reports the checkout being
    written to, which is not necessarily the installed Prowler.

    Args:
        repo_root: The repository root.

    Returns:
        The built-in provider names, sorted.
    """
    providers_root = repo_root / "prowler" / "providers"
    if not providers_root.is_dir():
        return []
    return sorted(
        entry.name
        for entry in providers_root.iterdir()
        if entry.is_dir()
        and entry.name != "common"
        and (entry / "__init__.py").is_file()
    )


def next_exception_code_range(repo_root: Path) -> Tuple[int, int]:
    """Suggest the next free block of provider exception codes.

    Args:
        repo_root: The repository root.

    Returns:
        The (start, end) of the suggested block.
    """
    highest = EXCEPTION_CODE_FLOOR - 1
    providers_root = repo_root / "prowler" / "providers"
    for exceptions_file in providers_root.glob("*/exceptions/exceptions.py"):
        for match in re.finditer(r"\((\d{4,6}),", exceptions_file.read_text()):
            highest = max(highest, int(match.group(1)))
    start = ((highest // EXCEPTION_CODE_BLOCK) + 1) * EXCEPTION_CODE_BLOCK
    return start, start + EXCEPTION_CODE_BLOCK - 1


def _dynamic_fallback_line(repo_root: Path) -> Optional[int]:
    """Find the line the built-in dispatch chain ends on.

    Args:
        repo_root: The repository root.

    Returns:
        The 1-indexed line of the dynamic fallback branch, or None.
    """
    provider_py = repo_root / "prowler" / "providers" / "common" / "provider.py"
    if not provider_py.is_file():
        return None
    for index, line in enumerate(provider_py.read_text().splitlines(), start=1):
        if "Dynamic fallback" in line:
            return index
    return None


def _indent(block: str, spaces: int = 4) -> str:
    """Indent every non-empty line of a rendered block."""
    pad = " " * spaces
    return "".join(
        f"{pad}{line}" if line.strip() else line
        for line in block.splitlines(keepends=True)
    )


def _auth_context(spec: ProviderSpec) -> dict:
    """Build the auth-dependent half of the template context.

    ``--auth`` decides which credential arguments exist and what the TODO
    markers say. It never decides how credentials are resolved: that is the
    contributor's call, and the generated `setup_session` raises until they
    make it.
    """
    env = spec.env_prefix
    name = spec.name
    common = {
        "sensitive_arguments": "",
        "from_cli_args_extra": "",
    }
    if spec.auth == "env":
        return {
            **common,
            "init_extra_params": "",
            "init_extra_docs": "",
            "session_def_params": "",
            "session_call_args": "",
            "session_test_args": "",
            "test_connection_params": "",
            "test_connection_docs": "",
            "auth_label": "Environment variables",
            "auth_docstring": (
                f"Credentials come from the {env}_* environment variables, which "
                "keeps secrets out of shell history and process listings."
            ),
            "auth_hint": (
                f"Read the {env}_* environment variables and raise "
                f"{spec.class_prefix}CredentialsError when they are missing."
            ),
            "auth_arguments": templates.ARGUMENTS_AUTH_ENV.substitute(env_prefix=env),
        }
    if spec.auth == "token":
        return {
            **common,
            "sensitive_arguments": templates.SENSITIVE_ARGUMENTS.substitute(name=name),
            "init_extra_params": "        token: str = None,\n",
            "init_extra_docs": (
                f"            token: {spec.class_prefix} API token, falling back "
                f"to the {env}_TOKEN environment variable.\n"
            ),
            "session_def_params": "token: str = None",
            "session_call_args": "token=token",
            "session_test_args": 'token="not-a-real-token"',
            "test_connection_params": "        token: str = None,\n",
            "test_connection_docs": (
                f"            token: {spec.class_prefix} API token.\n"
            ),
            "auth_label": "API token",
            "auth_docstring": (
                "The token is taken from the argument when given, and from the "
                f"{env}_TOKEN environment variable otherwise."
            ),
            "auth_hint": (
                f"Fall back to os.environ.get('{env}_TOKEN') and raise "
                f"{spec.class_prefix}CredentialsError when neither is set."
            ),
            "auth_arguments": templates.ARGUMENTS_AUTH_TOKEN.substitute(
                name=name, env_prefix=env, class_prefix=spec.class_prefix
            ),
            "from_cli_args_extra": (
                f'            token=getattr(arguments, "{name}_token", None),\n'
            ),
        }
    if spec.auth == "key-file":
        return {
            **common,
            "init_extra_params": "        key_file: str = None,\n",
            "init_extra_docs": (
                "            key_file: Path to the credentials key file, "
                f"falling back to the {env}_KEY_FILE environment variable.\n"
            ),
            "session_def_params": "key_file: str = None",
            "session_call_args": "key_file=key_file",
            "session_test_args": 'key_file="/nonexistent/key.json"',
            "test_connection_params": "        key_file: str = None,\n",
            "test_connection_docs": (
                "            key_file: Path to the credentials key file.\n"
            ),
            "auth_label": "Key file",
            "auth_docstring": (
                "The key file path is taken from the argument when given, and "
                f"from the {env}_KEY_FILE environment variable otherwise."
            ),
            "auth_hint": (
                "Read and parse the key file, and raise "
                f"{spec.class_prefix}CredentialsError when it is missing or malformed."
            ),
            "auth_arguments": templates.ARGUMENTS_AUTH_KEY_FILE.substitute(
                name=name, env_prefix=env, class_prefix=spec.class_prefix
            ),
            "from_cli_args_extra": (
                f'            key_file=getattr(arguments, "{name}_key_file", None),\n'
            ),
        }
    # browser
    return {
        **common,
        "init_extra_params": "        browser_auth: bool = False,\n",
        "init_extra_docs": (
            "            browser_auth: Whether to authenticate with the "
            "interactive browser flow.\n"
        ),
        "session_def_params": "browser_auth: bool = False",
        "session_call_args": "browser_auth=browser_auth",
        "session_test_args": "browser_auth=False",
        "test_connection_params": "        browser_auth: bool = False,\n",
        "test_connection_docs": (
            "            browser_auth: Whether to use the interactive browser flow.\n"
        ),
        "auth_label": "Interactive browser",
        "auth_docstring": (
            "The interactive browser flow is used when browser_auth is set, so "
            "this path needs a human at a terminal and cannot run unattended."
        ),
        "auth_hint": (
            "Start the browser flow when browser_auth is set, and raise "
            f"{spec.class_prefix}CredentialsError when it is not."
        ),
        "auth_arguments": templates.ARGUMENTS_AUTH_BROWSER.substitute(
            name=name, env_prefix=env, class_prefix=spec.class_prefix
        ),
        "from_cli_args_extra": (
            f'            browser_auth=getattr(arguments, "{name}_browser_auth", False),\n'
        ),
    }


def _regional_context(spec: ProviderSpec) -> dict:
    """Build the region-dependent half of the template context."""
    if not spec.regional:
        return {
            "regions_init": "",
            "regions_property": "",
            "validate_regions": "",
            "regions_arguments": "",
            "regions_param": "",
            "regions_doc": "",
            "regions_from_cli_args": "",
        }
    return {
        "regions_init": templates.REGIONS_INIT.substitute(
            class_prefix=spec.class_prefix
        ),
        "regions_property": templates.REGIONS_PROPERTY.substitute(),
        "validate_regions": templates.VALIDATE_REGIONS.substitute(
            class_prefix=spec.class_prefix
        ),
        "regions_arguments": templates.ARGUMENTS_REGIONS.substitute(
            name=spec.name, class_prefix=spec.class_prefix
        ),
        "regions_param": "        regions: list = None,\n",
        "regions_doc": (
            "            regions: Region(s) to scan for regional resources. "
            "None scans every region.\n"
        ),
        "regions_from_cli_args": (
            '            regions=getattr(arguments, "region", None),\n'
        ),
    }


def _template_context(spec: ProviderSpec, repo_root: Optional[Path]) -> dict:
    """Assemble the full substitution context for one spec."""
    auth = _auth_context(spec)
    regional = _regional_context(spec)
    code_start, code_end = (
        next_exception_code_range(repo_root)
        if repo_root is not None
        else (EXCEPTION_CODE_FLOOR, EXCEPTION_CODE_FLOOR + EXCEPTION_CODE_BLOCK - 1)
    )
    # The parser local is only assigned when an argument actually uses it. A
    # provider with environment-only auth and no region filter adds no
    # arguments at all, and an unused local is an F841 in the tree CI lints.
    uses_parser = spec.auth != "env" or spec.regional
    return {
        "name": spec.name,
        "class_prefix": spec.class_prefix,
        "env_prefix": spec.env_prefix,
        "parser_assignment": f"{spec.name}_parser = " if uses_parser else "",
        "sdk_only_attr": "" if spec.sdk_only else "    sdk_only: bool = False\n",
        "sdk_only_value": "True" if spec.sdk_only else "False",
        "code_start": code_start,
        "code_end": code_end,
        "code_credentials": code_start,
        "code_session": code_start + 1,
        "code_identity": code_start + 2,
        **auth,
        **regional,
        # The auth params come first so that the credential arguments read
        # before the region filter, matching the existing providers.
        "init_extra_params": auth["init_extra_params"] + regional["regions_param"],
        "init_extra_docs": auth["init_extra_docs"] + regional["regions_doc"],
        "from_cli_args_extra": (
            auth["from_cli_args_extra"] + regional["regions_from_cli_args"]
        ),
    }


def _sorted_imports(*statements: str) -> str:
    """Order `from` imports by module path, the way isort's black profile does.

    Whether a provider's own imports sort before or after
    `prowler.providers.common` depends on its name, so this cannot be baked
    into the templates. The repository runs isort over `prowler/` and `tests/`
    in pre-commit, and sorting here is what keeps a contributor's first
    `prek run` from opening with a diff they did not write.

    Sorting the handful of statements the templates emit is deliberate rather
    than calling isort, which is only a transitive pin here and not a declared
    development dependency.
    """
    return "\n".join(
        sorted(
            (statement.strip("\n") for statement in statements),
            key=lambda statement: statement.split()[1],
        )
    )


def _format_python(source: str) -> str:
    """Format generated Python with black when it is importable.

    Prowler's CI runs `black --check` over the repository, so a generated
    provider has to be formatter-clean before the contributor's first push.
    black is a declared development dependency and is present in a checkout.
    When it is absent, which is the case for an external provider scaffolded
    from an installed Prowler, the source is written as rendered.
    """
    try:
        import black
    except ImportError:
        return source
    try:
        return black.format_str(source, mode=black.Mode())
    except Exception:
        # A template bug must surface as code to inspect, not a failed scaffold.
        return source


def _builtin_import_blocks(spec: ProviderSpec) -> dict:
    """Build the import blocks whose order depends on the provider's name."""
    name, cls = spec.name, spec.class_prefix
    return {
        "provider_class": _sorted_imports(
            "from prowler.providers.common.models import Audit_Metadata, Connection",
            "from prowler.providers.common.provider import Provider",
            f"from prowler.providers.{name}.exceptions.exceptions import (\n"
            f"    {cls}CredentialsError,\n"
            f"    {cls}IdentityError,\n"
            f"    {cls}SessionError,\n"
            ")",
            f"from prowler.providers.{name}.lib.mutelist.mutelist import {cls}Mutelist",
            f"from prowler.providers.{name}.models import (\n"
            f"    {cls}IdentityInfo,\n"
            f"    {cls}Session,\n"
            ")",
        ),
        "provider_test": _sorted_imports(
            f"from prowler.providers.{name}.exceptions.exceptions import (\n"
            f"    {cls}CredentialsError,\n"
            f"    {cls}IdentityError,\n"
            ")",
            f"from prowler.providers.{name}.{name}_provider import {cls}Provider",
        ),
        "provider_fixtures": _sorted_imports(
            f"from prowler.providers.{name}.{name}_provider import {cls}Provider",
            f"from prowler.providers.{name}.models import (\n"
            f"    {cls}IdentityInfo,\n"
            f"    {cls}Session,\n"
            ")",
        ),
    }


def build_builtin_plan(spec: ProviderSpec, repo_root: Path) -> ScaffoldPlan:
    """Plan the files for a provider that lives inside this repository."""
    ctx = _template_context(spec, repo_root)
    imports = _builtin_import_blocks(spec)
    name = spec.name
    base = f"prowler/providers/{name}"
    tests_base = f"tests/providers/{name}"

    files = {
        f"{base}/__init__.py": "",
        f"{base}/{name}_provider.py": _format_python(
            templates.PROVIDER_CLASS.substitute(
                **{**ctx, "provider_imports": imports["provider_class"]}
            )
        ),
        f"{base}/models.py": _format_python(templates.MODELS.substitute(**ctx)),
        f"{base}/exceptions/__init__.py": "",
        f"{base}/exceptions/exceptions.py": _format_python(
            templates.EXCEPTIONS.substitute(**ctx)
        ),
        f"{base}/lib/__init__.py": "",
        f"{base}/lib/arguments/__init__.py": "",
        f"{base}/lib/arguments/arguments.py": _format_python(
            templates.ARGUMENTS.substitute(**ctx)
        ),
        f"{base}/lib/mutelist/__init__.py": "",
        f"{base}/lib/mutelist/mutelist.py": _format_python(
            templates.MUTELIST.substitute(**ctx)
        ),
        # tests/ must not contain __init__.py; scripts/check_test_init_files.py
        # fails the build when one appears.
        f"{tests_base}/{name}_provider_test.py": _format_python(
            templates.PROVIDER_TEST.substitute(
                **{**ctx, "provider_imports": imports["provider_test"]}
            )
        ),
        f"{tests_base}/{name}_fixtures.py": _format_python(
            templates.PROVIDER_FIXTURES.substitute(
                **{**ctx, "provider_imports": imports["provider_fixtures"]}
            )
        ),
        f"{tests_base}/lib/arguments/{name}_arguments_test.py": _format_python(
            templates.ARGUMENTS_TEST.substitute(**ctx)
        ),
    }

    if spec.needs_services:
        files[f"{base}/lib/service/__init__.py"] = ""
        files[f"{base}/lib/service/service.py"] = _format_python(
            templates.SERVICE_BASE.substitute(**ctx)
        )
        files[f"{base}/services/__init__.py"] = templates.SERVICES_INIT.substitute()

    plan = ScaffoldPlan(root=repo_root, files=files)
    plan.next_steps = _builtin_next_steps(spec, repo_root, ctx)
    return plan


def _elif_snippet(spec: ProviderSpec, ctx: dict) -> str:
    """Render the dispatch branch to paste into init_global_provider()."""
    lines = [f'                elif arguments.provider == "{spec.name}":']
    lines.append("                    provider_class(")
    if spec.auth == "token":
        lines.append(
            f'                        token=getattr(arguments, "{spec.name}_token", None),'
        )
    elif spec.auth == "key-file":
        lines.append(
            f'                        key_file=getattr(arguments, "{spec.name}_key_file", None),'
        )
    elif spec.auth == "browser":
        lines.append(
            f'                        browser_auth=getattr(arguments, "{spec.name}_browser_auth", False),'
        )
    if spec.regional:
        lines.append(
            '                        regions=getattr(arguments, "region", None),'
        )
    lines.extend(
        [
            "                        config_path=arguments.config_file,",
            "                        mutelist_path=arguments.mutelist_file,",
            "                        fixer_config=fixer_config,",
            "                    )",
        ]
    )
    return "\n".join(lines)


def _builtin_next_steps(spec: ProviderSpec, repo_root: Path, ctx: dict) -> List[str]:
    """List the work the scaffold deliberately leaves to the contributor."""
    fallback_line = _dynamic_fallback_line(repo_root)
    location = (
        f"prowler/providers/common/provider.py:{fallback_line}"
        if fallback_line
        else "prowler/providers/common/provider.py"
    )
    steps = [
        "Search the generated files for TODO. Authentication, the identity "
        "mapping and the checks are yours to write.",
        "Wire argument parsing and instantiation into init_global_provider(). "
        f"Add this branch immediately before the dynamic fallback at {location}:"
        f"\n\n{_elif_snippet(spec, ctx)}\n",
        f"Add CheckReport{spec.class_prefix} to prowler/lib/check/models.py, then "
        f"annotate the finding argument in {spec.name}/lib/mutelist/mutelist.py "
        "with it. The names in that file are not derived from the provider "
        "name, so pick the spelling that matches its neighbours.",
        f"Confirm exception codes {ctx['code_start']} to {ctx['code_end']} are "
        "still free before you commit. The scaffold read the highest code in "
        "use at generation time.",
    ]
    if spec.needs_services:
        steps.append(
            f"Add the first service under prowler/providers/{spec.name}/services/. "
            "The scaffold stops at the package marker because a service name "
            "and its API calls are provider-specific."
        )
    else:
        steps.append(
            "This kind has no service layer, matching iac, image and llm. Drop "
            f"prowler/providers/{spec.name}/lib/mutelist/ too if this provider "
            "reports findings that a mutelist cannot address, as those three do."
        )
    if not spec.sdk_only:
        steps.append(
            "sdk_only is False, so the API and UI list this provider. The API "
            "and UI work is a separate scope: see the Full-Stack scope in the "
            "developer guide, and note that the UI step of the provider guide "
            "is still unwritten."
        )
    steps.extend(
        [
            "Add a changelog fragment, for example: echo 'Support for "
            f"{spec.class_prefix} as a new provider' > prowler/changelog.d/"
            f"{spec.name}-provider.added.md",
            "Verify: `prowler --help` lists the provider with its help text, "
            f"`prowler {spec.name} --help` shows its arguments, and "
            f"`pytest tests/providers/{spec.name}` passes.",
        ]
    )
    return steps


def build_external_plan(spec: ProviderSpec, output_dir: Path) -> ScaffoldPlan:
    """Plan the files for a provider distributed as its own package."""
    ctx = _template_context(spec, None)
    package = f"prowler_provider_{spec.name}"
    files = {
        "pyproject.toml": templates.EXTERNAL_PYPROJECT.substitute(**ctx),
        "README.md": templates.EXTERNAL_README.substitute(**ctx),
        f"{package}/__init__.py": "",
        # The external provider builds its subparser inside a method, so the
        # argument blocks need one extra level of indentation.
        f"{package}/provider.py": _format_python(
            templates.EXTERNAL_PROVIDER.substitute(
                **{
                    **ctx,
                    "auth_arguments": _indent(ctx["auth_arguments"]),
                    "regions_arguments": _indent(ctx["regions_arguments"]),
                }
            )
        ),
        f"{package}/models.py": _format_python(
            templates.EXTERNAL_MODELS.substitute(**ctx)
        ),
        "tests/test_provider.py": _format_python(
            templates.EXTERNAL_TEST.substitute(**ctx)
        ),
    }
    plan = ScaffoldPlan(root=output_dir, files=files)
    plan.next_steps = [
        "Search the generated files for TODO. Authentication, the identity "
        "mapping and the checks are yours to write.",
        "Install it next to Prowler: `pip install -e .` in this directory.",
        f"Verify discovery: `prowler --help` lists {spec.name}, and "
        f"`prowler {spec.name} --help` shows its arguments.",
        "Keep init_parser and from_cli_args. An external provider cannot join "
        "the built-in dispatch chain, so those two are what make it usable "
        "from the CLI, and no built-in provider implements them for you to "
        "copy from.",
        "Do not reuse a built-in provider name. Prowler ignores an "
        "entry-point provider that collides with a built-in.",
    ]
    return plan


def build_plan(spec: ProviderSpec, path: Optional[Path] = None) -> ScaffoldPlan:
    """Plan a scaffold run for one spec.

    Args:
        spec: The validated provider spec.
        path: For a built-in provider, the repository root, auto-detected when
            omitted. For an external provider, the directory to create,
            defaulting to ./prowler-provider-<name>.

    Returns:
        The plan, which writes nothing until write_plan() is called.

    Raises:
        ScaffoldError: If the target is not usable.
    """
    validate_name(spec.name)
    if spec.kind not in KINDS:
        raise ScaffoldError(
            f"Invalid kind '{spec.kind}'. Choose one of: {', '.join(KINDS)}."
        )
    if spec.scope not in SCOPES:
        raise ScaffoldError(
            f"Invalid scope '{spec.scope}'. Choose one of: {', '.join(SCOPES)}."
        )
    if spec.auth not in AUTH_MODES:
        raise ScaffoldError(
            f"Invalid auth mode '{spec.auth}'. Choose one of: {', '.join(AUTH_MODES)}."
        )

    if spec.scope == "external":
        output_dir = path or Path.cwd() / f"prowler-provider-{spec.name}"
        return build_external_plan(spec, output_dir.resolve())

    repo_root = find_repo_root(path) if path is None else path.resolve()
    if not (repo_root / "prowler" / "providers" / "common" / "provider.py").is_file():
        raise ScaffoldError(
            f"'{repo_root}' does not look like a Prowler checkout: "
            "prowler/providers/common/provider.py is missing."
        )
    if spec.name in existing_builtin_names(repo_root):
        raise ScaffoldError(
            f"Provider '{spec.name}' already exists at "
            f"prowler/providers/{spec.name}. Pick another name."
        )
    return build_builtin_plan(spec, repo_root)


def write_plan(plan: ScaffoldPlan, force: bool = False) -> List[Path]:
    """Write a plan to disk.

    Args:
        plan: The plan to write.
        force: Overwrite files that already exist.

    Returns:
        The written paths, sorted.

    Raises:
        ScaffoldError: If a target file exists and force is not set.
    """
    if not force:
        clashes = [
            relative for relative in plan.paths if (plan.root / relative).exists()
        ]
        if clashes:
            raise ScaffoldError(
                "Refusing to overwrite existing files:\n"
                + "\n".join(f"  {clash}" for clash in clashes)
                + "\nRe-run with --force to overwrite them."
            )

    written = []
    for relative in plan.paths:
        target = plan.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(plan.files[relative])
        written.append(target)
    return written
