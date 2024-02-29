from prowler.providers.azure.services.mysql.mysql_service import MySQL
from prowler.providers.common.common import get_global_provider

mysql_client = MySQL(get_global_provider())
