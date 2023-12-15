from concurrent.futures import ThreadPoolExecutor, as_completed

from prowler.lib.logger import logger
from prowler.lib.ui.live_display import live_display
from prowler.providers.aws.aws_provider import (
    generate_regional_clients,
    get_default_region,
)
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

MAX_WORKERS = 10


class AWSService:
    """The AWSService class offers a parent class for each AWS Service to generate:
    - AWS Regional Clients
    - Shared information like the account ID and ARN, the the AWS partition and the checks audited
    - AWS Session
    - Thread pool for the __threading_call__
    - Also handles if the AWS Service is Global
    """

    def __init__(self, service: str, audit_info: AWS_Audit_Info, global_service=False):
        # Audit Information
        self.audit_info = audit_info
        self.audited_account = audit_info.audited_account
        self.audited_account_arn = audit_info.audited_account_arn
        self.audited_partition = audit_info.audited_partition
        self.audit_resources = audit_info.audit_resources
        self.audited_checks = audit_info.audit_metadata.expected_checks
        self.audit_config = audit_info.audit_config

        # AWS Session
        self.session = audit_info.audit_session

        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: AccessAnalyzer --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service

        # Generate Regional Clients
        if not global_service:
            self.regional_clients = generate_regional_clients(self.service, audit_info)

        # Get a single region and client if the service needs it (e.g. AWS Global Service)
        # We cannot include this within an else because some services needs both the regional_clients
        # and a single client like S3
        self.region = get_default_region(self.service, audit_info)
        self.client = self.session.client(self.service, self.region)

        # Thread pool for __threading_call__
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

        # Progress bar to add tasks to
        current_section = live_display.get_current_section()
        self.progress = current_section.task_progress
        self.progress_tasks = []
        self.title_bar = current_section.title_bar

        self.title_bar_task = self.title_bar.add_task(
            f"Intializing {self.service} service:", start=False, task_type="Service"
        )

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call, iterator=None):
        # Use the provided iterator, or default to self.regional_clients
        items = iterator if iterator is not None else self.regional_clients.values()
        # Determine the total count for logging
        item_count = len(items)

        # Trim leading and trailing underscores from the call's name
        call_name = call.__name__.strip("_")
        # Add Capitalization
        call_name = " ".join([x.capitalize() for x in call_name.split("_")])

        # Print a message based on the call's name, and if its regional or processing a list of items
        if iterator is None:
            logger.info(
                f"{self.service.upper()} - Starting threads for '{call_name}' function across {item_count} regions..."
            )
        else:
            logger.info(
                f"{self.service.upper()} - Starting threads for '{call_name}' function to process {item_count} items..."
            )

        # Setup the progress bar
        task_id = self.progress.add_task(
            f"- {call_name}...", total=item_count, task_type="Service"
        )
        self.progress_tasks.append(task_id)

        # Submit tasks to the thread pool
        futures = [self.thread_pool.submit(call, item) for item in items]

        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()  # Raises exceptions from the thread, if any
                # Update the progress bar
                self.progress.update(task_id, advance=1)
            except Exception:
                # Handle exceptions if necessary
                pass  # Replace 'pass' with any additional exception handling logic. Currently handled within the called function

        # Make the task disappear once completed
        # self.progress.remove_task(task_id)

    def __update_progress_is_complete__(self):
        self.title_bar.update(
            self.title_bar_task,
            description=f"Completed initilization for {self.service}",
        )
        for task_id in self.progress_tasks:
            self.progress.remove_task(task_id)

    def __clear_ui__(self):
        self.title_bar.remove_task(self.title_bar_task)
        for task_id in self.progress_tasks:
            self.progress.remove_task(task_id)
