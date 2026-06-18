from typing import Optional

# Cloudflare returns the plan name in ``zone.plan.name`` (e.g. "Free Website",
# "Pro Website", "Business Website", "Enterprise Website"). Free plans do not
# expose WAF managed rulesets at all, while paid plans expose them but the
# legacy ``waf`` zone setting can lag behind the actual deployment state.
PAID_PLAN_KEYWORDS = ("pro", "business", "enterprise")
FREE_PLAN_KEYWORDS = ("free",)


def _plan_matches(plan: Optional[str], keywords: tuple[str, ...]) -> bool:
    if not isinstance(plan, str):
        return False
    plan_lower = plan.lower()
    return any(keyword in plan_lower for keyword in keywords)


def is_paid_plan(plan: Optional[str]) -> bool:
    """Return True when the Cloudflare zone plan is a paid tier."""
    return _plan_matches(plan, PAID_PLAN_KEYWORDS)


def is_free_plan(plan: Optional[str]) -> bool:
    """Return True when the Cloudflare zone plan is the Free tier."""
    return _plan_matches(plan, FREE_PLAN_KEYWORDS)


def paid_plan_suffix(plan: Optional[str], message: str) -> str:
    """Return an explanatory suffix only when the zone is on a paid plan."""
    return f" {message}" if is_paid_plan(plan) else ""


def free_plan_suffix(plan: Optional[str], message: str) -> str:
    """Return an explanatory suffix only when the zone is on the Free plan."""
    return f" {message}" if is_free_plan(plan) else ""
