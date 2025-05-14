from rest_framework.response import Response


class PaginateByPkMixin:
    """
    Mixin to paginate on a list of PKs (cheaper than heavy JOINs),
    re-fetch the full objects with the desired select/prefetch,
    re-sort them to preserve DB ordering, then serialize + return.
    """

    def paginate_by_pk(
        self,
        request,  # noqa: F841
        base_queryset,
        manager,
        select_related: list[str] | None = None,
        prefetch_related: list[str] | None = None,
    ) -> Response:
        pk_list = base_queryset.values_list("id", flat=True)
        page = self.paginate_queryset(pk_list)
        if page is None:
            return Response(self.get_serializer(base_queryset, many=True).data)

        queryset = manager.filter(id__in=page)
        if select_related:
            queryset = queryset.select_related(*select_related)
        if prefetch_related:
            queryset = queryset.prefetch_related(*prefetch_related)

        queryset = sorted(queryset, key=lambda obj: page.index(obj.id))

        serialized = self.get_serializer(queryset, many=True).data
        return self.get_paginated_response(serialized)
