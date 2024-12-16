from contextlib import nullcontext

from rest_framework_json_api.renderers import JSONRenderer

from api.db_utils import rls_transaction


class APIJSONRenderer(JSONRenderer):
    """JSONRenderer override to apply tenant RLS when there are included resources in the request."""

    def render(self, data, accepted_media_type=None, renderer_context=None):
        request = renderer_context.get("request")
        tenant_id = getattr(request, "tenant_id", None) if request else None
        include_param_present = "include" in request.query_params if request else False

        # Use rls_transaction if needed for included resources, otherwise do nothing
        context_manager = (
            rls_transaction(tenant_id)
            if tenant_id and include_param_present
            else nullcontext()
        )
        with context_manager:
            return super().render(data, accepted_media_type, renderer_context)
