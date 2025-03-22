from prowler.providers.ionos.services.compute.compute_service import {
    IonosCompute,
}
from prowler.providers.common.provider import Provider

ionos_compute_client = IonosCompute(Provider.get_global_provider())