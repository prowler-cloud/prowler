from drf_spectacular_jsonapi.schemas.pagination import JsonApiPageNumberPagination


class ComplianceOverviewPagination(JsonApiPageNumberPagination):
    page_size = 50
    max_page_size = 100
