from pydantic import BaseModel


class Audit_Metadata(BaseModel):
    services_scanned: int
    checks_launched: int
    checks_progress: int
