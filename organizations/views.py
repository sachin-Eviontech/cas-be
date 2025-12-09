from django.shortcuts import render
from .models import Organization
from .serializers import OrganizationSerializer
from .permissions import CanCreateOrganizations,CanDeleteOrganizations,CanUpdateOrganizations,CanViewOrganizations
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from django_filters import rest_framework as filters
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser

# Create your views here.

class OrganizationsViewSet(viewsets.ModelViewSet):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny]
    serializer_class = OrganizationSerializer
    queryset = Organization.objects.all()

    filter_backends = (
        filters.DjangoFilterBackend,
        OrderingFilter,
        SearchFilter,
    )
    filterset_fields = {
        "name" : ["in", "exact"]
    }
    ordering_fields = [
        "name",
        "logo",
        "message",
        "packageName",
        "showWarning",
        "blockAccess",
    ]
    search_fields = [
        "name",
        "logo",
        "message",
        "packageName",
        "showWarning",
        "blockAccess",
    ]
    
    ordering = ['id']

    # def get_permissions(self):
    #     permission_classes = [IsAuthenticated]

    #     if self.action == "create":
    #         permission_classes += [CanCreateOrganizations]
    #     if self.action == "list":
    #         permission_classes += [CanViewOrganizations]
    #     if self.action == "retrieve":
    #         permission_classes += [CanViewOrganizations]
    #     if self.action in ["update", "partial_update"]:
    #         permission_classes += [CanUpdateOrganizations]
    #     if self.action in ["destroy"]:
    #         permission_classes += [CanDeleteOrganizations]

    #     return [permission() for permission in permission_classes]
    
    def create(self,request):
        serializer = OrganizationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"status":True, "message":"Organization created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
    


