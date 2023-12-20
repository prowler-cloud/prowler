from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps

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

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call, iterator=None, max_workers=10, *args, **kwargs):
        # Use the provided iterator, or default to self.regional_clients
        items = iterator if iterator is not None else self.regional_clients.values()

        # Using ThreadPoolExecutor for managing threads
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit tasks to the executor
            futures = [executor.submit(call, item, *args, **kwargs) for item in items]

            # Wait for all tasks to complete
            for future in as_completed(futures):
                try:
                    future.result()  # Raises exceptions from the thread, if any
                except Exception:
                    # Handle exceptions if necessary
                    pass  # Replace 'pass' with any additional exception handling logic

    def progress_decorator(self, func):
        """Decorator to update the progress bar before and after a function call."""

        @wraps(func)
        def wrapper(*args, **kwargs):
            task_name = func.__name__.replace("_", " ").capitalize()
            task_id = self.task_progress_bar.add_task(
                f"- {task_name}...", total=1, task_type="Service"
            )
            self.progress_tasks.append(task_id)

            result = func(*args, **kwargs)  # Execute the function

            self.task_progress_bar.update(task_id, advance=1)
            # self.task_progress_bar.remove_task(task_id)  # Uncomment if you want to remove the task on completion

            return result

        return wrapper
