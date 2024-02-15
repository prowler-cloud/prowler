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
from prowler.providers.aws.models import AWSIdentityInfo, AWSAssumeRole

# Defines a subclass of Live for creating and managing the live display in the CLI
class LiveDisplay(Live):
    def __init__(self, *args, **kwargs):
        # Load a theme for the console display from a file
        theme = self.load_theme_from_file()
        super().__init__(renderable=None, console=Console(theme=theme), *args, **kwargs)
        self.sections = {}  # Stores different sections of the layout
        self.enabled = False # Flag to enable or disable the live display

    # Sets up the layout of the live display
    def make_layout(self):
        """
        Defines the layout.
        Making sections invisible so it doesnt show the default Layout metadata before content is added
        Text(" ") is to stop the layout metadata from rendering before the layout is updated with real content
        client_and_service handles client init (when importing clients) and service check execution
        """
        self.layout = Layout(name="root")
        # Split layout into intro, overall progress, and main sections
        self.layout.split(
            Layout(name="intro", ratio=3, minimum_size=9),
            Layout(Text(" "), name="overall_progress", minimum_size=5),
            Layout(name="main", ratio=10),
        )
        # Further split intro layout into body and creds sections
        self.layout["intro"].split_row(
            Layout(name="body", ratio=3),
            Layout(name="creds", ratio=2, visible=False),
        )
        # Split main layout into client_and_service and results sections
        self.layout["main"].split_row(
            Layout(
                Text(" "), name="client_and_service", ratio=3
            ),  # For client_init and service
            Layout(name="results", ratio=2, visible=False),
        )

    # Loads a theme from a YAML file located in the same directory as this file
    def load_theme_from_file(self):
        # Loads theme.yaml from the same folder as this file
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open(f"{actual_directory}/theme.yaml") as f:
            theme = Theme.from_file(f)
        return theme

    # Initializes the layout and sections based on CLI arguments
    def initialize(self, args):
        # A way to get around parsing args to LiveDisplay when it is intialized
        # This is so that the live_display object can be intialized in this file, and imported to other parts of prowler
        self.cli_args = args

        self.enabled = not args.only_logs

        if self.enabled:
            # Initialize layout
            self.make_layout()
            # Apply layout
            self.update(self.layout)
            # Add Intro section
            intro_layout = self.layout["intro"]
            intro_section = IntroSection(args, intro_layout)
            self.sections["intro"] = intro_section
            # Start live display
            self.start()

    # Adds AWS credentials to the display
    def print_aws_credentials(self, aws_identity_info: AWSIdentityInfo, assumed_role_info: AWSAssumeRole):
        # Adds the AWS credentials to the display - will need to extend to gcp and azure
        # Create a new function for gcp and azure in this class, that will call a function in the intro_section class
        intro_section = self.sections["intro"]
        intro_section.add_aws_credentials(aws_identity_info, assumed_role_info)

    # Adds and manages the overall progress section
    def add_overall_progress_section(self, total_checks_dict):
        overall_progress_section = OverallProgressSection(total_checks_dict)
        overall_progress_layout = self.layout["overall_progress"]
        overall_progress_layout.update(overall_progress_section)
        overall_progress_layout.visible = True
        self.sections["overall_progress"] = overall_progress_section

        # Add results section
        self.add_results_section()

    # Wrapper function to increment the overall progress
    def increment_overall_check_progress(self):
        # Called by ExecutionManager
        if self.enabled:
            section = self.sections["overall_progress"]
            section.increment_check_progress()

    # Wrapper function to increment the progress for the current service
    def increment_overall_service_progress(self):
        # Called by ExecutionManager
        if self.enabled:
            section = self.sections["overall_progress"]
            section.increment_service_progress()

    # Adds and manages the results section
    def add_results_section(self):
        # Intializes the results section
        results_layout = self.layout["results"]
        results_section = ResultsSection()
        results_layout.update(results_section)
        results_layout.visible = True
        self.sections["results"] = results_section

    def add_results_for_service(self, service_name, service_findings):
        # Adds rows to the Service Check Results table
        if self.enabled:
            results_section = self.sections["results"]
            results_section.add_results_for_service(service_name, service_findings)

    # Client Init Section
    def add_client_init_section(self, service_name):
        # Used to track progress of client init process
        if self.enabled:
            client_init_section = ClientInitSection(service_name)
            self.sections["client_and_service"] = client_init_section
            self.layout["client_and_service"].update(client_init_section)
            self.layout["client_and_service"].visible = True

    # Service Section
    def add_service_section(self, service_name, total_checks):
        # Used to create the ServiceSection when checks start to execute (after clients have been imported)
        if self.enabled:
            service_section = ServiceSection(service_name, total_checks)
            self.sections["client_and_service"] = service_section
            self.layout["client_and_service"].update(service_section)

    def increment_check_progress(self):
        if self.enabled:
            service_section = self.sections["client_and_service"]
            service_section.increment_check_progress()

    # Misc
    def get_service_section(self):
        # Used by Check
        if self.enabled:
            return self.sections["client_and_service"]

    def get_client_init_section(self):
        # Used by AWSService
        if self.enabled:
            return self.sections["client_and_service"]

    def hide_service_section(self):
        # To hide the last service after execution has completed
        self.layout["client_and_service"].visible = False

    def print_message(self, message):
        # No use yet
        self.console.print(message)

# The following classes (ServiceSection, ClientInitSection, IntroSection, OverallProgressSection, ResultsSection)
# are used to define different sections of the live display, each with its own layout, progress bars,

class ServiceSection:
    def __init__(self, service_name, total_checks) -> None:
        self.service_name = service_name
        self.total_checks = total_checks
        self.renderables = self.create_service_section()
        self.start_check_progress()

    def __rich__(self):
        return Padding(self.renderables, (2, 2))

    def create_service_section(self):
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

    def start_check_progress(self):
        self.check_progress_task_id = self.check_progress.add_task(
            "Checks executed", total=self.total_checks
        )

    def increment_check_progress(self):
        self.check_progress.update(self.check_progress_task_id, advance=1)


class ClientInitSection:
    def __init__(self, client_name) -> None:
        self.client_name = client_name
        self.renderables = self.create_client_init_section()

    def __rich__(self):
        return Padding(self.renderables, (2, 2))

    def create_client_init_section(self):
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
        self.creds_layout = layout["creds"]
        self.renderables = []
        self.title = f"Prowler v{prowler_version}"
        if not args.no_banner:
            self.create_banner(args)

    def __rich__(self):
        return Group(*self.renderables)

    def create_banner(self, args):
        banner_text = f"""[banner_color]                         _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v{prowler_version}
|_|[/banner_color][banner_blue]the handy cloud security tool[/banner_blue]

[info]Date: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}[/info]
        """

        if args.verbose:
            banner_text += """
Color code for results:
- [info]INFO (Information)[/info]
- [pass]PASS (Recommended value)[/pass]
- [orange_color]WARNING (Ignored by mutelist)[/orange_color]
- [fail]FAIL (Fix required)[/fail]
                """
        self.renderables.append(banner_text)
        self.body_layout.update(Group(*self.renderables))
        self.body_layout.visible = True

    def add_aws_credentials(self, aws_identity_info: AWSIdentityInfo, assumed_role_info: AWSAssumeRole):
        # Beautify audited regions, and set to "all" if there is no filter region
        regions = (
            ", ".join(aws_identity_info.audited_regions)
            if aws_identity_info.audited_regions is not None
            else "all"
        )
        # Beautify audited profile, set and to "default" if there is no profile set
        profile = aws_identity_info.profile if aws_identity_info.profile is not None else "default"

        content = Text()
        content.append(
            "This report is being generated using credentials below:\n\n", style="bold"
        )

        content.append("AWS-CLI Profile: ", style="bold")
        content.append(f"[{profile}]\n", style="info")

        content.append("AWS Filter Region: ", style="bold")
        content.append(f"[{regions}]\n", style="info")

        content.append("AWS Account: ", style="bold")
        content.append(f"[{aws_identity_info.account}]\n", style="info")

        content.append("UserId: ", style="bold")
        content.append(f"[{aws_identity_info.user_id}]\n", style="info")

        content.append("Caller Identity ARN: ", style="bold")
        content.append(f"[{aws_identity_info.identity_arn}]\n", style="info")
        # If a role has been assumed, print the Assumed Role ARN
        if assumed_role_info.role_arn is not None:
            content.append("Assumed Role ARN: ", style="bold")
            content.append(f"[{assumed_role_info.role_arn}]\n", style="info")

        self.creds_layout.update(content)
        self.creds_layout.visible = True


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
