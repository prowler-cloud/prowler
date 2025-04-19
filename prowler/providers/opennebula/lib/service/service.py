from prowler.providers.opennebula.opennebula_provider import OpennebulaProvider

class OpennebulaService:
    def __init__(self, provider: OpennebulaProvider):
        self.provider = provider
        self.client = provider.session.client
        self.identity = provider.identity
        self.audit_config = provider.audit_config
        self.output_options = provider.output_options
        self.mutelist = provider.mutelist
