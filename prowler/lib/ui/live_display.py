import os
import pathlib

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
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
from rich.theme import Theme

from prowler.lib.logger import logger


class LiveDisplay(Live):
    def __init__(self, *args, **kwargs):
        theme = self.__load_theme_from_file__()
        super().__init__(renderable=None, console=Console(theme=theme), *args, **kwargs)
        self.sections = {}
        self.ordered_section_names = []  # List to remember the order of sections
        self.current_section = None

    def has_section(self, section_name):
        return section_name in self.sections.keys()

    def add_service_section(self, service_name, total_checks):
        # Create a new section for the service
        if service_name in self.sections:
            logger.error(f"Section already exists for {service_name}")
            return
        service_section = ServiceSection(service_name, total_checks)
        self.sections[service_name] = service_section
        self.ordered_section_names.append(service_name)  # Store the order
        self.current_section = service_name
        self.__update_layout__()

    def get_current_section(self):
        if not self.current_section:
            logger.error(
                "LiveDisplay has not been intialized! No current section to return"
            )
            return
        return self.sections[self.current_section]

    def print_message(self, message):
        self.console.print(message)

    def __update_layout__(self):
        # Just a basic layout for now. Will be improved
        # Create a group of renderables based on the order of sections
        renderables = [
            self.sections[name].renderables for name in self.ordered_section_names
        ]
        grouped_renderables = Group(*renderables)

        # Update the existing layout
        self.update(grouped_renderables)

    def __load_theme_from_file__(self):
        # Loads theme.yaml from the same folder as this file
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open(f"{actual_directory}/theme.yaml") as f:
            theme = Theme.from_file(f)
        return theme

    # Wrappers to call the increment_progress in the ServiceSection class objects
    def increment_check_progress(self):
        current_section = self.get_current_section()
        if not isinstance(current_section, ServiceSection):
            logger.error("Current section is not set or not a ServiceSection")
            return
        current_section.increment_check_progress()

    def add_summary_table_for_service(self, service_findings):
        current_section = self.get_current_section()
        if not isinstance(current_section, ServiceSection):
            logger.error("Current section is not set or not a ServiceSection")
            return
        current_section.add_summary_table_for_service(service_findings)
        self.update()


class ServiceSection:
    def __init__(self, service_name, total_checks) -> None:
        self.service_name = service_name
        self.total_checks = total_checks
        self.renderables = self.__create_service_section__()
        self.__start_check_progress__()

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
                f"[{status.lower()}]{str(count)}[/{status.lower()}]",
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


class ServiceInitSection:
    def __init__(self) -> None:
        pass


# Create an instance of LiveDisplay to import elsewhere (ExecutionManager, the checks, the services)

live_display = LiveDisplay()
