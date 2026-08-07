from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.e2enetworks.lib.service.service import E2eNetworksService


class LoadBalancers(E2eNetworksService):
    """Service class for E2E Networks load balancers."""

    def __init__(self, provider):
        super().__init__("loadbalancer", provider)
        self.load_balancers: list[LoadBalancer] = []
        self._fetch_loadbalancers()

    def _fetch_loadbalancers(self):
        for location in self.provider.session.locations:
            try:
                appliances = self.client.paginate(
                    "/appliances/",
                    location=location,
                )
                for item in appliances:
                    context = self._extract_context(item)
                    node_detail = item.get("node_detail", {}) or {}
                    self.load_balancers.append(
                        LoadBalancer(
                            id=str(item.get("id", "")),
                            name=item.get("name", ""),
                            location=location,
                            status=item.get("status", ""),
                            lb_mode=context.get("lb_mode", ""),
                            lb_port=str(context.get("lb_port", "")),
                            enable_bitninja=bool(context.get("enable_bitninja", False)),
                            ssl_certificate_id=self._get_ssl_certificate_id(context),
                            backends=context.get("backends", []) or [],
                            public_ip=node_detail.get("public_ip", ""),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"loadbalancer - Error fetching appliances in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    @staticmethod
    def _extract_context(item: dict) -> dict:
        instances = item.get("appliance_instance", []) or []
        if not instances:
            return {}
        return instances[0].get("context", {}) or {}

    @staticmethod
    def _get_ssl_certificate_id(context: dict) -> str | None:
        ssl_context = context.get("ssl_context", {}) or {}
        certificate_id = ssl_context.get("ssl_certificate_id")
        if certificate_id in (None, "", 0):
            return None
        return str(certificate_id)


class LoadBalancer(BaseModel):
    id: str
    name: str
    location: str
    status: str = ""
    lb_mode: str = ""
    lb_port: str = ""
    enable_bitninja: bool = False
    ssl_certificate_id: str | None = None
    backends: list = []
    public_ip: str = ""

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name

    @property
    def is_alb(self) -> bool:
        mode = self.lb_mode.upper()
        return mode in ("HTTP", "HTTPS", "BOTH")

    @property
    def is_alb_https(self) -> bool:
        mode = self.lb_mode.upper()
        return mode in ("HTTPS", "BOTH")

    @property
    def has_backend_health_check(self) -> bool:
        for backend in self.backends:
            if isinstance(backend, dict) and backend.get("http_check"):
                return True
        return False
