from prowler.providers.snowflake.snowflake_provider import SnowflakeProvider


class SnowflakeService:
    """Base class for Snowflake services to share provider context."""

    def __init__(self, provider: SnowflakeProvider):
        """
        Initialize the Snowflake service with provider context.

        Args:
            provider: SnowflakeProvider instance containing session, identity and configuration.
        """
        self.provider = provider
        self.client = provider.session.client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.account = provider.identity.account
