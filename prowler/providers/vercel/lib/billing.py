from typing import Optional

from prowler.providers.common.provider import Provider


def extract_billing_plan(data: Optional[dict]) -> Optional[str]:
    """Return the Vercel billing plan from a user or team payload.

    Vercel's REST API consistently returns the plan identifier at
    ``data["billing"]["plan"]`` (e.g. ``"hobby"``, ``"pro"``, ``"enterprise"``)
    on both ``GET /v2/user`` and ``GET /v2/teams`` responses, even though the
    field is not part of the public OpenAPI schema.
    """
    if not isinstance(data, dict):
        return None
    billing = data.get("billing")
    if not isinstance(billing, dict):
        return None
    plan = billing.get("plan")
    return plan.lower() if isinstance(plan, str) else None


def resolve_scope_billing_plan(scope_id: Optional[str] = None) -> Optional[str]:
    """Resolve the billing plan for a Vercel scope ID, if it is available."""
    provider = Provider.get_global_provider()
    identity = getattr(provider, "identity", None)
    if not identity:
        return None

    if scope_id:
        if (
            identity.team
            and identity.team.id == scope_id
            and identity.team.billing_plan
        ):
            return identity.team.billing_plan

        for team in identity.teams:
            if team.id == scope_id and team.billing_plan:
                return team.billing_plan

        if identity.user_id == scope_id:
            return identity.billing_plan

        return None

    if identity.team and identity.team.billing_plan:
        return identity.team.billing_plan

    return identity.billing_plan


def plan_reason_suffix(
    billing_plan: Optional[str], unsupported_plans: set[str], explanation: str
) -> str:
    """Return a plan-based explanation suffix only when the plan proves it."""
    if billing_plan in unsupported_plans:
        return f" This may be expected because {explanation}"
    return ""
