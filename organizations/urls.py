from django.conf import settings
from .views import OrganizationsViewSet
from rest_framework.routers import DefaultRouter, SimpleRouter

if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("", OrganizationsViewSet, "organization")

urlpatterns = []
urlpatterns += router.urls
