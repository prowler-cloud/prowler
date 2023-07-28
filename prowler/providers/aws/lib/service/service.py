from prowler.providers.aws.aws_provider import (
    generate_regional_clients,
    get_default_region,
)


class AWS_Service:
    """The AWS_Service class offers a parent class for each AWS Service to generate:
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
        if not self.service.islower():
            # e.g.: AccessAnalyzer --> we need a lowercase string, so service.lower()
            self.service = service.lower()

        # Generate Regional Clients
        if not global_service:
            self.regional_clients = generate_regional_clients(
                self.service, audit_info, global_service
            )

        # Get a single region and client if the service needs it (e.g. AWS Global Service)
        self.region = get_default_region(self.service, audit_info)
        self.client = self.session.client(self.service, self.region)
