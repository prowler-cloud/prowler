from rich.console import Group
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

# Overall Progress Bar
overall_progress = Progress(
    TextColumn("[bold blue]{task.description}", justify="right"),
    BarColumn(bar_width=None),
    MofNCompleteColumn(),
    transient=False,  # Optional: set True if you want the progress bar to disappear after completion
)

# Title progress bar (no bar or n/m complete)
title_bar = Progress(
    TextColumn("[progress.description]{task.description}"), transient=True
)

# Service Initialization Progress Bar
task_progress = Progress(
    TextColumn("[progress.description]{task.description}"),
    BarColumn(bar_width=None),
    MofNCompleteColumn(),
    TimeElapsedColumn(),
    TimeRemainingColumn(),
    transient=True,
)

# Table for the live object
# progress_table = Table.grid()
# progress_table.add_row(
#     Panel.fit(
#         overall_progress, title="Overall Progress", border_style="green", padding=(2, 2)
#     ),
#     Panel.fit(service_init_progress, title="[b]Service Initialization", border_style="red", padding=(1, 2)),
#     Panel.fit(checks_progress, title="[b]Check Progress", border_style="red", padding=(1, 2)),
# )

progress_table = Group(
    Panel(Group(overall_progress, Rule(style="bold blue"), title_bar, task_progress)),
)


def clear_progress_tasks():
    for progress_bar in [task_progress, title_bar]:
        for task_id in progress_bar.task_ids:
            progress_bar.remove_task(task_id)
