from prowler.providers.common.provider import Provider
from prowler.providers.kubernetes.services.etcd.etcd_service import Etcd

etcd_client = Etcd(Provider.get_global_provider())
