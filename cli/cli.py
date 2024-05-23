import typer

from prowler.lib.banner import print_banner
from prowler.lib.check.check import list_services, print_services

app = typer.Typer()
listers = typer.Typer()
app.add_typer(listers, name="listers")


@listers.command(
    "list-services", help="List all the services that are supported by the tool."
)
def listServices(provider: str = "aws"):
    print_services(list_services(provider))


@app.command("banner", help="Prints the banner of the tool.")
def banner(show: bool = True):
    if show:
        print_banner(show)
    else:
        print("Banner is not shown.")


if __name__ == "__main__":
    app()
