from prowler.providers.aws.aws_provider import (
    generate_regional_clients,
    get_default_region,
)


class AWS_Service:
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

        # We receive the service using __class__.__name__
        # e.g.: AccessAnalyzer --> we need a lowercase string, so service.lower()
        self.service = service.lower()

        # Generate Regional Clients
        self.regional_clients = generate_regional_clients(
            self.service, audit_info, global_service
        )

        # Get a single region if the service needs it
        self.region = get_default_region(self.service, audit_info)
        if self.service in ["iam", "fms", "s3", "organizations"]:
            self.client = self.session.client(self.service, self.region)

        # If the service is global we need to set a single client and a region
        # that replaces the default region set
        if global_service:
            self.client = list(self.regional_clients.values())[0]
            self.region = self.client.region
