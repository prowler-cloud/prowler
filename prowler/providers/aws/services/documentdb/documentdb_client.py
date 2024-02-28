from prowler.providers.aws.services.documentdb.documentdb_service import DocumentDB
from prowler.providers.common.common import get_global_provider

documentdb_client = DocumentDB(get_global_provider())
