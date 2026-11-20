import pytest

from prowler.lib.dev.cli import build_parser, main


class Test_build_parser:
    def test_parses_the_documented_invocation(self):
        """The invocation the issue documents has to keep working."""
        arguments = build_parser().parse_args(
            [
                "provider",
                "create",
                "--name",
                "acmecloud",
                "--kind",
                "api",
                "--scope",
                "full-stack",
                "--regional",
                "false",
                "--auth",
                "token",
            ]
        )

        assert arguments.name == "acmecloud"
        assert arguments.kind == "api"
        assert arguments.scope == "full-stack"
        assert arguments.regional == "false"
        assert arguments.auth == "token"

    def test_defaults_to_environment_auth_and_no_regions(self):
        arguments = build_parser().parse_args(
            [
                "provider",
                "create",
                "--name",
                "acmecloud",
                "--kind",
                "api",
                "--scope",
                "builtin",
            ]
        )

        assert arguments.auth == "env"
        assert arguments.regional == "false"
        assert arguments.path is None
        assert arguments.dry_run is False
        assert arguments.force is False

    @pytest.mark.parametrize(
        "missing",
        [
            ["provider", "create", "--kind", "api", "--scope", "builtin"],
            ["provider", "create", "--name", "acmecloud", "--scope", "builtin"],
            ["provider", "create", "--name", "acmecloud", "--kind", "api"],
        ],
    )
    def test_the_three_explicit_inputs_are_required(self, missing):
        """Name, kind and scope each change what gets generated, so the
        command refuses to guess them."""
        with pytest.raises(SystemExit):
            build_parser().parse_args(missing)

    @pytest.mark.parametrize(
        "invalid",
        [
            ["--kind", "serverless"],
            ["--scope", "everything"],
            ["--auth", "telepathy"],
            ["--regional", "maybe"],
        ],
    )
    def test_rejects_values_outside_the_documented_choices(self, invalid):
        base = [
            "provider",
            "create",
            "--name",
            "acmecloud",
            "--kind",
            "api",
            "--scope",
            "builtin",
        ]
        with pytest.raises(SystemExit):
            build_parser().parse_args(base + invalid)


class Test_main:
    def test_dry_run_writes_nothing(self, tmp_path, capsys):
        target = tmp_path / "out"

        exit_code = main(
            [
                "provider",
                "create",
                "--name",
                "acmecloud",
                "--kind",
                "api",
                "--scope",
                "external",
                "--path",
                str(target),
                "--dry-run",
            ]
        )

        assert exit_code == 0
        assert not target.exists()
        assert "Would create" in capsys.readouterr().out

    def test_create_writes_the_files_and_reports_next_steps(self, tmp_path, capsys):
        target = tmp_path / "out"

        exit_code = main(
            [
                "provider",
                "create",
                "--name",
                "acmecloud",
                "--kind",
                "api",
                "--scope",
                "external",
                "--path",
                str(target),
            ]
        )
        output = capsys.readouterr().out

        assert exit_code == 0
        assert (target / "pyproject.toml").is_file()
        assert (target / "prowler_provider_acmecloud" / "provider.py").is_file()
        assert "Created" in output
        assert "Next steps:" in output

    def test_a_rejected_name_exits_nonzero_and_explains_why(self, tmp_path, capsys):
        exit_code = main(
            [
                "provider",
                "create",
                "--name",
                "acme_cloud",
                "--kind",
                "api",
                "--scope",
                "external",
                "--path",
                str(tmp_path / "out"),
            ]
        )

        assert exit_code == 1
        assert "str.capitalize()" in capsys.readouterr().err

    def test_an_existing_provider_name_exits_nonzero(self, capsys):
        exit_code = main(
            [
                "provider",
                "create",
                "--name",
                "aws",
                "--kind",
                "api",
                "--scope",
                "builtin",
            ]
        )

        assert exit_code == 1
        assert "already exists" in capsys.readouterr().err

    def test_refusing_to_overwrite_exits_nonzero(self, tmp_path, capsys):
        arguments = [
            "provider",
            "create",
            "--name",
            "acmecloud",
            "--kind",
            "api",
            "--scope",
            "external",
            "--path",
            str(tmp_path / "out"),
        ]
        assert main(arguments) == 0
        capsys.readouterr()

        exit_code = main(arguments)

        assert exit_code == 1
        assert "Refusing to overwrite" in capsys.readouterr().err

    def test_force_overwrites(self, tmp_path, capsys):
        arguments = [
            "provider",
            "create",
            "--name",
            "acmecloud",
            "--kind",
            "api",
            "--scope",
            "external",
            "--path",
            str(tmp_path / "out"),
        ]
        assert main(arguments) == 0
        capsys.readouterr()

        assert main(arguments + ["--force"]) == 0
