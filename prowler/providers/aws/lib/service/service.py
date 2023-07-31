import threading

from prowler.providers.aws.aws_provider import (
    generate_regional_clients,
    get_default_region,
)


class AWSService:
    """The AWSService class offers a parent class for each AWS Service to generate:
    - AWS Regional Clients
    - Shared information like the account ID and ARN, the the AWS partition and the checks audited
    - AWS Session
    - Also handles if the AWS Service is Global
    """

    def __init__(self, service, audit_info, global_service=False):
        # Audit Information
        self.audit_info = audit_info
        self.audited_account = audit_info.audited_account
        self.audited_account_arn = audit_info.audited_account_arn
        self.audited_partition = audit_info.audited_partition
        self.audit_resources = audit_info.audit_resources
        self.audited_checks = audit_info.audit_metadata.expected_checks

        # AWS Session
        self.session = audit_info.audit_session

        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: AccessAnalyzer --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service

        # Generate Regional Clients
        if not global_service:
            self.regional_clients = generate_regional_clients(
                self.service, audit_info, global_service
            )

        # Get a single region and client if the service needs it (e.g. AWS Global Service)
        self.region = get_default_region(self.service, audit_info)
        self.client = self.session.client(self.service, self.region)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
