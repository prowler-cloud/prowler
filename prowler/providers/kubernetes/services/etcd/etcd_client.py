from prowler.providers.common.common import global_provider
from prowler.providers.kubernetes.services.etcd.etcd_service import Etcd

etcd_client = Etcd(global_provider)
