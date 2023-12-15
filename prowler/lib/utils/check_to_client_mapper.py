import ast
import os
import pathlib

from prowler.lib.logger import logger


class CheckFileFinder(ast.NodeVisitor):
    def __init__(self):
        self.is_check_file = False

    def visit_ClassDef(self, node):
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == "Check":
                self.is_check_file = True
                break
        self.generic_visit(node)


class ImportFinder(ast.NodeVisitor):
    def __init__(self, provider):
        self.imports = set()
        self.provider = provider

    def visit_ImportFrom(self, node):
        if node.module and f"prowler.providers.{self.provider}.services" in node.module:
            for name in node.names:
                if "_client" in name.name:
                    self.imports.add(name.name)
        self.generic_visit(node)


def get_dependencies_for_checks(provider, checks_dict):
    def analyze_check_file(file_path, provider):
        # Prase the check file
        with open(file_path, "r") as file:
            node = ast.parse(file.read(), filename=file_path)

        finder = ImportFinder(provider)
        finder.visit(node)
        return list(finder.imports)

    current_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
    prowler_dir = current_directory.parent.parent
    check_dependencies = {}
    for service_name, checks in checks_dict.items():
        check_dependencies[service_name] = {}
        for check_name in checks:
            relative_path = f"providers/{provider}/services/{service_name}/{check_name}/{check_name}.py"
            check_file_path = prowler_dir / relative_path
            if not check_file_path.exists():
                logger.error(
                    f"{check_name} does not exist at {relative_path}! Cannot determine service dependencies"
                )
                continue
            clients = analyze_check_file(str(check_file_path), provider)
            check_dependencies[service_name][check_name] = clients
    return check_dependencies
