import os
import pathlib
from datetime import timedelta
from time import time

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from prowler.config.config import prowler_version, timestamp
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info


class LiveDisplay(Live):
    def __init__(self, *args, **kwargs):
        theme = self.__load_theme_from_file__()
        super().__init__(renderable=None, console=Console(theme=theme), *args, **kwargs)
        self.sections = {}
        self.current_section = None
        self.make_layout()

    def get_service_section(self):
        # Used by Check
        return self.sections["client_and_service"]

    def get_client_init_section(self):
        # Used by AWSService
        return self.sections["client_and_service"]

    def add_service_section(self, service_name, total_checks):
        # Used to create the ServiceSection when checks start to execute (after clients have been imported)
        service_section = ServiceSection(service_name, total_checks)
        self.sections["client_and_service"] = service_section
        self.layout["client_and_service"].update(service_section)

    def hide_service_section(self):
        # To hide the last service after execution has completed
        self.layout["client_and_service"].visible = False

    def print_message(self, message):
        # No use yet
        self.console.print(message)

    def make_layout(self):
        """
        Defines the layout.
        Making sections invisible so it doesnt show the default Layout metadata before content is added
        Text(" ") is to stop the layout metadata from rendering before the layout is updated with real content
        client_and_service handles client init (when importing clients) and service check execution
        """
        self.layout = Layout(name="root")
        self.layout.split(
            Layout(name="intro", ratio=3, minimum_size=9),
            Layout(Text(" "), name="overall_progress", minimum_size=5),
            Layout(name="main", ratio=10),
        )
        self.layout["intro"].split_row(
            Layout(name="body", ratio=3),
            Layout(name="side", ratio=2, visible=False),
        )
        self.layout["main"].split_row(
            Layout(
                Text(" "), name="client_and_service", ratio=3
            ),  # For client_init and service
            Layout(name="results", ratio=2, visible=False),
        )

    def __load_theme_from_file__(self):
        # Loads theme.yaml from the same folder as this file
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open(f"{actual_directory}/theme.yaml") as f:
            theme = Theme.from_file(f)
        return theme

    # Wrappers for ServiceSection methods
    def increment_check_progress(self):
        service_section = self.sections["client_and_service"]
        service_section.increment_check_progress()

    # Results Section Methods
    def add_results_section(self):
        # Intializes the results section
        results_layout = self.layout["results"]
        results_section = ResultsSection()
        results_layout.update(results_section)
        results_layout.visible = True
        self.sections["results"] = results_section

    def add_results_for_service(self, service_name, service_findings):
        # Adds rows to the Service Check Results table
        results_section = self.sections["results"]
        results_section.add_results_for_service(service_name, service_findings)

    # Client Init Methods
    def add_client_init_section(self, service_name):
        client_init_section = ClientInitSection(service_name)
        # self.add_section("client_and_service", client_init_section, default_section=True)
        self.sections["client_and_service"] = client_init_section
        self.layout["client_and_service"].update(client_init_section)
        self.layout["client_and_service"].visible = True
        self.update(self.layout)

    # Intro Section Methods
    def add_intro(self, args):
        # A way to get around parsing args to LiveDisplay when it is intialized
        # This is so that the live_display object can be intialized in this file, and imported to other parts of prowler
        self.cli_args = args
        intro_layout = self.layout["intro"]
        intro_section = IntroSection(args, intro_layout)
        self.sections["intro"] = intro_section
        self.update(self.layout)

    def print_aws_credentials(self, audit_info):
        # Adds the AWS credentials to the display - will need to extend to gcp and azure
        intro_section = self.sections["intro"]
        intro_section.add_aws_credentials(audit_info)

    # Overall Progress Methods
    def add_overall_progress_section(self, total_checks_dict):
        overall_progress_section = OverallProgressSection(total_checks_dict)
        overall_progress_layout = self.layout["overall_progress"]
        overall_progress_layout.update(overall_progress_section)
        overall_progress_layout.visible = True
        self.sections["overall_progress"] = overall_progress_section

        # Add results section
        self.add_results_section()
        self.update(self.layout)

    def increment_overall_check_progress(self):
        # Called by ExecutionManager
        section = self.sections["overall_progress"]
        section.increment_check_progress()

    def increment_overall_service_progress(self):
        # Called by ExecutionManager
        section = self.sections["overall_progress"]
        section.increment_service_progress()


class ServiceSection:
    def __init__(self, service_name, total_checks) -> None:
        self.service_name = service_name
        self.total_checks = total_checks
        self.renderables = self.__create_service_section__()
        self.__start_check_progress__()

    def __rich__(self):
        return Padding(self.renderables, (2, 2))

    def __create_service_section__(self):
        # Create the progress components
        self.check_progress = Progress(
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            transient=False,  # Optional: set True if you want the progress bar to disappear after completion
        )

        # Used to add titles that dont need progress bars
        self.title_bar = Progress(
            TextColumn("[progress.description]{task.description}"), transient=True
        )
        # Progress Bar for Service Init and Checks
        self.task_progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=True,
        )

        return Group(
            Panel(
                Group(
                    self.check_progress,
                    Rule(style="bold blue"),
                    self.title_bar,
                    Rule(style="bold blue"),
                    self.task_progress,
                ),
                title=f"Service: {self.service_name}",
            ),
        )

    def __start_check_progress__(self):
        self.check_progress_task_id = self.check_progress.add_task(
            "Checks executed", total=self.total_checks
        )

    def increment_check_progress(self):
        self.check_progress.update(self.check_progress_task_id, advance=1)

    def add_summary_table_for_service(self, service_findings):
        # Calculate the total number of checks
        total_checks = len(service_findings)

        # Create a new renderable to show the results
        results_table = Table(title="Service Check Results")
        results_table.add_column("Result", justify="right")
        results_table.add_column("Count", justify="center")
        results_table.add_column("Percentage", justify="center")

        # For each status type, determine the count and percentage
        statuses = list(set([report.status for report in service_findings]))
        for status in statuses:
            count = len(
                [report for report in service_findings if report.status == status]
            )
            percentage = (count / total_checks * 100) if total_checks else 0
            results_table.add_row(
                f"{status.capitalize()}",
                f"[{status.lower()}]{str(count)}[/{status.lower()}]",  # Add the rich theme defined in theme.yaml
                f"{percentage:.2f}%",
            )

        # Create a centered Panel
        centered_results_table = Panel(Align.center(results_table))

        # Replace the task_progress in the progress_table
        self.renderables = Group(
            Panel(
                Group(
                    self.check_progress,
                    Rule(style="bold blue"),
                    self.title_bar,
                    Rule(style="bold blue"),
                    centered_results_table,  # Replacing task_progress with results_table
                ),
                title=f"Service: {self.service_name}",
            ),
        )


class ClientInitSection:
    def __init__(self, client_name) -> None:
        self.client_name = client_name
        self.renderables = self.__create_client_init_section__()

    def __rich__(self):
        return Padding(self.renderables, (2, 2))

    def __create_client_init_section__(self):
        # Progress Bar for Checks
        self.task_progress_bar = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=True,
        )

        return Group(
            Panel(
                Group(
                    self.task_progress_bar,
                ),
                title=f"Intializing {self.client_name.replace('_', ' ')}",
            ),
        )


class IntroSection:
    def __init__(self, args, layout: Layout) -> None:
        self.body_layout = layout["body"]
        self.side_layout = layout["side"]
        self.renderables = []
        self.title = f"Prowler v{prowler_version}"
        if not args.no_banner:
            self.__create_banner__(args)

    def __rich__(self):
        return Group(*self.renderables)

    def __create_banner__(self, args):
        banner_text = f"""[banner_color]                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v{prowler_version}
|_|[/banner_color][banner_blue]the handy cloud security tool[/banner_blue]

[info]Date: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}[/info]
        """

        if args.verbose or args.quiet or True:
            banner_text += """
Color code for results:
- [info]INFO (Information)[/info]
- [pass]PASS (Recommended value)[/pass]
- [orange_color]WARNING (Ignored by allowlist)[/orange_color]
- [fail]FAIL (Fix required)[/fail]
                """
        self.renderables.append(banner_text)
        self.body_layout.update(Group(*self.renderables))
        self.body_layout.visible = True

    def add_aws_credentials(self, audit_info: AWS_Audit_Info):
        # Beautify audited regions, set "all" if there is no filter region
        regions = (
            ", ".join(audit_info.audited_regions)
            if audit_info.audited_regions is not None
            else "all"
        )
        # Beautify audited profile, set "default" if there is no profile set
        profile = audit_info.profile if audit_info.profile is not None else "default"

        content = Text()
        content.append(
            "This report is being generated using credentials below:\n\n", style="bold"
        )

        content.append("AWS-CLI Profile: ", style="bold")
        content.append(f"[{profile}]\n", style="info")

        content.append("AWS Filter Region: ", style="bold")
        content.append(f"[{regions}]\n", style="info")

        content.append("AWS Account: ", style="bold")
        content.append(f"[{audit_info.audited_account}]\n", style="info")

        content.append("UserId: ", style="bold")
        content.append(f"[{audit_info.audited_user_id}]\n", style="info")

        content.append("Caller Identity ARN: ", style="bold")
        content.append(f"[{audit_info.audited_identity_arn}]\n", style="info")
        # If -A is set, print Assumed Role ARN
        if audit_info.assumed_role_info.role_arn is not None:
            content.append("Assumed Role ARN: ", style="bold")
            content.append(f"[{audit_info.assumed_role_info.role_arn}]\n", style="info")

        self.side_layout.update(content)
        self.side_layout.visible = True


class OverallProgressSection:
    def __init__(self, total_checks_dict: dict) -> None:
        self.start_time = time()  # Start the timer
        self.renderables = self.create_renderable(total_checks_dict)

    def __rich__(self):
        elapsed_time = self.total_time_taken()
        return Group(*self.renderables, f"Total time taken: {elapsed_time}")

    def total_time_taken(self):
        elapsed_seconds = int(time() - self.start_time)
        elapsed_time = timedelta(seconds=elapsed_seconds)
        return elapsed_time

    def create_renderable(self, total_checks_dict):
        services_num = len(total_checks_dict)  # number of keys == number of services
        checks_num = sum(total_checks_dict.values())

        plural_string = "checks"
        singular_string = "check"

        check_noun = plural_string if checks_num > 1 else singular_string

        # Create the progress bar
        self.overall_progress_bar = Progress(
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            transient=False,  # Optional: set True if you want the progress bar to disappear after completion
        )
        # Create the Services Completed task, to track the number of services completed
        self.service_progress_task_id = self.overall_progress_bar.add_task(
            "Services completed", total=services_num
        )
        # Create the Checks Completed task, to track the number of checks completed across all services
        self.check_progress_task_id = self.overall_progress_bar.add_task(
            "Checks executed", total=checks_num
        )

        content = Text()
        content.append(
            f"Executing {checks_num} {check_noun} across {services_num} services, please wait...\n",
            style="bold",
        )

        return [content, self.overall_progress_bar]

    def increment_check_progress(self):
        self.overall_progress_bar.update(self.check_progress_task_id, advance=1)

    def increment_service_progress(self):
        self.overall_progress_bar.update(self.service_progress_task_id, advance=1)


class ResultsSection:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.table = Table(title="Service Check Results")
        self.table.add_column("Service", justify="left")

        if self.verbose:
            self.serverities = ["critical", "high", "medium", "low"]
            # Add columns for each severity level when verbose, report on the count of fails per severity per service
            for severity in self.serverities:
                styled_header = (
                    f"[{severity.lower()}]{severity.capitalize()}[/{severity.lower()}]"
                )
                self.table.add_column(styled_header, justify="center")

        else:
            # Dynamically track the status's, report on the status counts for each service
            self.status_columns = set(["PASS", "FAIL"])
            self.service_findings = {}  # Dictionary to store findings for each service

            # Dictionary to map plain statuses to their stylized forms
            self.status_headers = {
                "FAIL": "[fail]Fail[/fail]",
                "PASS": "[pass]Pass[/pass]",
            }

            # Add the initial columns with styling
            for status, header in self.status_headers.items():
                self.table.add_column(header, justify="center")

    def add_results_for_service(self, service_name, service_findings):
        if self.verbose:
            # Count fails per severity
            severity_counts = {severity: 0 for severity in self.serverities}
            for finding in service_findings:
                if finding.status == "FAIL":
                    severity_counts[finding.check_metadata.Severity] += 1

            # Add row with severity counts
            row = [service_name] + [
                str(severity_counts[severity]) for severity in self.serverities
            ]
            self.table.add_row(*row)
        else:
            # Update the dictionary with the new findings
            status_counts = {report.status: 0 for report in service_findings}
            for report in service_findings:
                status_counts[report.status] += 1
            self.service_findings[service_name] = status_counts

            # Update status_columns and table columns
            self.status_columns.update(status_counts.keys())
            for status in self.status_columns:
                if status not in self.status_headers:
                    # [{status.lower()}] is for the styling (defined in theme.yaml)
                    # If new status, add it to status_headers and table
                    styled_header = (
                        f"[{status.lower()}]{status.capitalize()}[/{status.lower()}]"
                    )
                    self.status_headers[status] = styled_header
                    self.table.add_column(styled_header, justify="center")

            # Update the table with findings for all services
            self._update_table()

    def _update_table(self):
        # Used for when verbose = false
        # Clear existing rows
        self.table.rows.clear()

        # Add updated rows for all services
        for service, counts in self.service_findings.items():
            row = [service]
            for status in self.status_columns:
                count = counts.get(status, 0)
                percentage = (
                    f"{(count / sum(counts.values()) * 100):.2f}%" if counts else "0%"
                )
                row.append(f"{count} ({percentage})")
            self.table.add_row(*row)

    def __rich__(self):
        # This method allows the ResultsSection to be directly rendered by Rich
        if not self.table.rows:
            return Text("")
        return Padding(Align.center(self.table), (0, 2))


# Create an instance of LiveDisplay to import elsewhere (ExecutionManager, the checks, the services)

live_display = LiveDisplay(vertical_overflow="visible")
