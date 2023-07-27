from prowler.providers.aws.aws_provider import (
    generate_regional_clients,
    get_default_region,
)


class AWS_Service:
    def __init__(self, service, audit_info, global_service=False):
        # We receive the service using __class__.__name__
        # e.g.: AccessAnalyzer --> we need a lowercase string, so service.lower()
        self.service = service.lower()
        self.audit_info = audit_info
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audited_account_arn = audit_info.audited_account_arn
        self.audited_partition = audit_info.audited_partition
        self.audit_resources = audit_info.audit_resources
        self.region = get_default_region(self.service, audit_info)
        self.regional_clients = generate_regional_clients(
            self.service, audit_info, global_service
        )
        self.audited_checks = audit_info.audit_metadata.expected_checks

        # Check this for S3
        if self.service in ["iam", "fms", "s3", "organizations"]:
            self.client = self.session.client(self.service, self.region)

        # Check this
        if global_service:
            self.client = list(self.regional_clients.values())[0]
            self.region = self.client.region
