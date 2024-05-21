from prowler.providers.aws.services.backup.backup_service import Backup
from prowler.providers.common.provider import Provider

backup_client = Backup(Provider.get_global_provider())
