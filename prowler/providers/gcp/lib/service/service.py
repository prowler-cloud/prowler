from prowler.providers.gcp.gcp_provider import generate_client


class GCPService:
    def __init__(self, service, audit_info, region="global", api_version="v1"):
        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: APIKeys --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service

        self.api_version = api_version
        self.project_ids = audit_info.project_ids
        self.default_project_id = audit_info.default_project_id

        self.region = region
        self.client = generate_client(service, api_version, audit_info)

    def __get_client__(self):
        return self.client
