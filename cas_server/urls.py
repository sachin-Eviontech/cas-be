"""
URL configuration for cas_server project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.documentation import include_docs_urls
from rest_framework.schemas import get_schema_view
from rest_framework import permissions

# API Documentation
schema_view = get_schema_view(
    title="CAS Server API",
    description="Central Authentication Service API Documentation",
    version="1.0.0",
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('cas/', include('cas_app.urls')),
    path('api/', include('cas_app.api_urls')),
    
    # API Documentation
    path('api/docs/', include_docs_urls(title='CAS Server API Documentation')),
    path('api/schema/', schema_view, name='api_schema'),
    path('api/documentation/', schema_view, name='api_documentation'),
    # Custom documentation will be available at /api/docs/ and /api/schema/
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
