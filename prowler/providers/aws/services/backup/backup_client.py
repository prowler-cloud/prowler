from prowler.providers.aws.services.backup.backup_service import Backup
from prowler.providers.common.common import get_global_provider

backup_client = Backup(get_global_provider())
