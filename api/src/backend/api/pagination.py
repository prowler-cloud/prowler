from rest_framework_json_api.pagination import JsonApiPageNumberPagination


class ComplianceOverviewPagination(JsonApiPageNumberPagination):
    page_size = 50
    max_page_size = 100
