class AzureService:
    def __init__(self, service, audit_info):
        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: Storage --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service

        self.credentials = audit_info.credentials
        self.subscriptions = audit_info.identity.subscriptions
