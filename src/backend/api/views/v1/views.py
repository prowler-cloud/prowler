from rest_framework import generics

from api.models import TestModel
from api.serializers import TestModelSerializer


class TestModelCreateView(generics.ListCreateAPIView):
    queryset = TestModel.objects.all()
    serializer_class = TestModelSerializer


class TestModelRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = TestModel.objects.all()
    serializer_class = TestModelSerializer
