from prowler.providers.common.provider import Provider
from prowler.providers.fly.services.machine.machine_service import Machine

machine_client = Machine(Provider.get_global_provider())
