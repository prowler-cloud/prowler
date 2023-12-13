import os
import pathlib

from rich.console import Console, Group
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
from rich.theme import Theme


class ProgressManager:
    """
    Keeps the progress_table for each service
        This is passed to Live() to be rendered
    overall_progress: tracks the checks progress
    title_bar: used to let the user know what is happening/has happened
    task_progress: shows a progress bar of what is happening
    """

    def __init__(self, service_name: str, total_checks: int, console: Console):
        self.service_name = service_name
        self.total_checks = total_checks
        self.console = console
        self.create_progress_table()

    def create_progress_table(self):
        # Create the progress components
        self.overall_progress = Progress(
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

        self.progress_table = Group(
            Panel(
                Group(
                    self.overall_progress,
                    Rule(style="bold blue"),
                    self.title_bar,
                    Rule(style="bold blue"),
                    self.task_progress,
                ),
                title=f"Service: {self.service_name}",
            ),
        )

        self.overall_progress_task_id = self.overall_progress.add_task(
            "Checks executed", total=self.total_checks
        )

    def clear_service_init_titles(self):
        service_init_tasks = [
            task.id
            for task in self.title_bar.tasks
            if task.fields.get("task_type") == "Service"
        ]
        for task_id in service_init_tasks:
            self.title_bar.remove_task(task_id)

    def increment_progress(self):
        self.overall_progress.update(self.overall_progress_task_id, advance=1)


class ActiveProgressManager:
    """
    Used to keep track of the current progress manager, so that the current progress manager can be dynamically imported into services/checks
    Also handles loading the theme, passing it to the console, and passing that console to the progress managers as they are created
    Needs to be intialized before being imported into checks/services
    """

    def __init__(self):
        theme = self.load_theme_from_file()
        self.console = Console(theme=theme)
        self.managers = {}
        self.current_manager = None

    def load_theme_from_file(self):
        # Loads theme.yaml from the same folder as this file
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open(f"{actual_directory}/theme.yaml") as f:
            theme = Theme.from_file(f)
        return theme

    def get_current_manager(self):
        return self.current_manager

    def set_current_manager(self, progress_manager: ProgressManager):
        self.current_manager = progress_manager

    def create_manager(self, service_name: str, total_checks: int):
        if service_name not in self.managers:
            self.managers[service_name] = ProgressManager(
                service_name, total_checks, self.console
            )
        self.current_manager = self.managers[service_name]


progress_manager = ActiveProgressManager()
