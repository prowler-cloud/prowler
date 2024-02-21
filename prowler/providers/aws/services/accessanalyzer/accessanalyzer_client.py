from prowler.providers.aws.services.accessanalyzer.accessanalyzer_service import (
    AccessAnalyzer,
)
from prowler.providers.common.common import get_global_provider

accessanalyzer_client = AccessAnalyzer(get_global_provider())
