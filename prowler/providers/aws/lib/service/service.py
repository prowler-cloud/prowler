import threading

from prowler.providers.aws.aws_provider_new import AwsProvider


class AWSService:
    """The AWSService class offers a parent class for each AWS Service to generate:
    - AWS Regional Clients
    - Shared information like the account ID and ARN, the the AWS partition and the checks audited
    - AWS Session
    - Also handles if the AWS Service is Global
    """

    def __init__(self, service: str, provider: AwsProvider, global_service=False):
        # Audit Information
        self.audited_account = provider.identity.account
        self.audited_account_arn = provider.identity.account_arn
        self.audited_partition = provider.identity.partition
        self.audit_resources = provider.audit_resources
        self.audited_checks = provider.audit_metadata.expected_checks
        self.audit_config = provider.audit_config

        # AWS Session
        self.session = provider.session.session

        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: AccessAnalyzer --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service

        # Generate Regional Clients
        if not global_service:
            self.regional_clients = provider.generate_regional_clients(
                self.service, global_service
            )

        # Get a single region and client if the service needs it (e.g. AWS Global Service)
        # We cannot include this within an else because some services needs both the regional_clients
        # and a single client like S3
        self.region = provider.get_default_region(self.service)
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
