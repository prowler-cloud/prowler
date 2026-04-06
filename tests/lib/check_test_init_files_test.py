from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "check_test_init_files.py"
)


def load_guard_module():
    spec = spec_from_file_location("check_test_init_files", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None

    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_find_test_init_files_detects_only_test_directories(tmp_path):
    guard = load_guard_module()

    (tmp_path / "tests" / "providers" / "aws").mkdir(parents=True)
    (tmp_path / "tests" / "providers" / "aws" / "__init__.py").write_text("")
    (tmp_path / "api" / "tests" / "performance").mkdir(parents=True)
    (tmp_path / "api" / "tests" / "performance" / "__init__.py").write_text("")
    (tmp_path / "prowler" / "providers" / "aws").mkdir(parents=True)
    (tmp_path / "prowler" / "providers" / "aws" / "__init__.py").write_text("")
    (
        tmp_path / "tests" / "lib" / "check" / "fixtures" / "checks_folder" / "check11"
    ).mkdir(parents=True)
    (
        tmp_path
        / "tests"
        / "lib"
        / "check"
        / "fixtures"
        / "checks_folder"
        / "check11"
        / "__init__.py"
    ).write_text("")

    matches = guard.find_test_init_files(tmp_path)

    assert [path.relative_to(tmp_path) for path in matches] == [
        Path("api/tests/performance/__init__.py"),
        Path("tests/providers/aws/__init__.py"),
    ]


def test_main_returns_error_when_test_init_files_exist(tmp_path, capsys):
    guard = load_guard_module()

    (tmp_path / "tests" / "config").mkdir(parents=True)
    (tmp_path / "tests" / "config" / "__init__.py").write_text("")

    assert guard.main([str(tmp_path)]) == 1

    captured = capsys.readouterr()
    assert "Remove __init__.py files from test directories" in captured.out
    assert "tests/config/__init__.py" in captured.out


def test_repository_has_no_test_init_files():
    guard = load_guard_module()

    repo_root = Path(__file__).resolve().parents[2]

    assert guard.find_test_init_files(repo_root) == []
