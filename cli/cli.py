import typer

from prowler.lib.banner import print_banner
from prowler.lib.check.check import (
    list_fixers,
    list_services,
    print_fixers,
    print_services,
)

app = typer.Typer()
aws = typer.Typer(name="aws")
azure = typer.Typer(name="azure")
gcp = typer.Typer(name="gcp")
kubernetes = typer.Typer(name="kubernetes")

app.add_typer(aws, name="aws")
app.add_typer(azure, name="azure")
app.add_typer(gcp, name="gcp")
app.add_typer(kubernetes, name="kubernetes")


def list_resources(provider: str, resource_type: str):
    if resource_type == "services":
        print_services(list_services(provider))
    elif resource_type == "fixers":
        print_fixers(list_fixers(provider))


def create_list_commands(provider_typer: typer.Typer):
    provider_name = provider_typer.info.name

    @provider_typer.command(
        "list-services",
        help=f"List the {provider_name} services that are supported by Prowler.",
    )
    def list_services_command():
        list_resources(provider_name, "services")

    @provider_typer.command(
        "list-fixers",
        help=f"List the {provider_name} fixers that are supported by Prowler.",
    )
    def list_fixers_command():
        list_resources(provider_name, "fixers")


create_list_commands(aws)
create_list_commands(azure)
create_list_commands(gcp)
create_list_commands(kubernetes)


@app.command("banner", help="Prints the banner of the tool.")
def banner(show: bool = True):
    if show:
        print_banner(show)
    else:
        print("Banner is not shown.")


if __name__ == "__main__":
    app()
