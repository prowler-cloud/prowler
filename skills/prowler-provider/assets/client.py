# Example: Singleton Client Pattern
# Source: prowler/providers/github/services/repository/repository_client.py

"""
Singleton Client Pattern

This pattern is CRITICAL for how Prowler checks access service data.

How it works:
1. When this module is imported, the service is instantiated ONCE
2. The service fetches all data during __init__ (eager loading)
3. All checks import this singleton and access pre-fetched data
4. No additional API calls needed during check execution

File: prowler/providers/github/services/repository/repository_client.py
"""

from prowler.providers.common.provider import Provider
from prowler.providers.github.services.repository.repository_service import Repository

# SINGLETON: Instantiated once when module is first imported
# Provider.get_global_provider() returns the provider set in __init__
repository_client = Repository(Provider.get_global_provider())


"""
Usage in checks:

from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)

class repository_secret_scanning_enabled(Check):
    def execute(self):
        findings = []
        for repo in repository_client.repositories.values():
            # Access pre-fetched repository data
            report = CheckReportGithub(metadata=self.metadata(), resource=repo)
            if repo.secret_scanning_enabled:
                report.status = "PASS"
            else:
                report.status = "FAIL"
            findings.append(report)
        return findings
"""


# Another example for organization service
# File: prowler/providers/github/services/organization/organization_client.py

# from prowler.providers.common.provider import Provider
# from prowler.providers.github.services.organization.organization_service import (
#     Organization,
# )
#
# organization_client = Organization(Provider.get_global_provider())
