from prowler.providers.common.common import get_global_provider
from prowler.providers.kubernetes.services.etcd.etcd_service import Etcd

etcd_client = Etcd(get_global_provider())
