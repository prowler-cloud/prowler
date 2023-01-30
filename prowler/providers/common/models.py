from pydantic import BaseModel


class Audit_Metadata(BaseModel):
    services_scanned: int
    expected_checks: int
    completed_checks: int
    audit_progress: int
