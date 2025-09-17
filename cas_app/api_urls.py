from django.urls import path
from . import api_views
from . import token_views
from . import documentation_views

urlpatterns = [
    # Root API endpoint
    path('', api_views.api_root, name='api_root'),
    
    # Authentication endpoints
    path('auth/login/', api_views.api_login, name='api_login'),
    path('auth/logout/', api_views.api_logout, name='api_logout'),
    path('auth/validate/', api_views.api_validate, name='api_validate'),
    path('auth/user/', api_views.api_user_info, name='api_user_info'),
    
    # Service-specific token authentication endpoints
    path('token/login/', token_views.token_login, name='token_login'),
    path('token/refresh/', token_views.token_refresh, name='token_refresh'),
    path('token/logout/', token_views.token_logout, name='token_logout'),
    path('token/validate/', token_views.token_validate, name='token_validate'),
    path('token/user/', token_views.token_user_info, name='token_user_info'),
    path('user/services/', token_views.get_user_services, name='get_user_services'),
    
    # Convenience endpoints (aliases for common CAS operations)
    path('validate/', api_views.api_validate, name='api_validate_direct'),
    
    # Service management
    path('services/', api_views.ServiceListCreateView.as_view(), name='api_service_list'),
    path('services/<int:pk>/', api_views.ServiceDetailView.as_view(), name='api_service_detail'),
    
    # User data
    path('tickets/', api_views.TicketListView.as_view(), name='api_ticket_list'),
    path('logs/', api_views.AuthenticationLogListView.as_view(), name='api_log_list'),
    path('profile/', api_views.UserProfileView.as_view(), name='api_profile'),
    
    # Admin endpoints
    path('admin/stats/', api_views.api_stats, name='api_stats'),
    
    # Access Management endpoints
    path('service-groups/', api_views.ServiceGroupListCreateView.as_view(), name='api_service_group_list'),
    path('service-groups/<int:pk>/', api_views.ServiceGroupDetailView.as_view(), name='api_service_group_detail'),
    path('access/service/', api_views.UserServiceAccessListView.as_view(), name='api_user_service_access'),
    path('access/group/', api_views.UserGroupAccessListView.as_view(), name='api_user_group_access'),
    path('access/accessible-services/', api_views.api_accessible_services, name='api_accessible_services'),
    path('access/request/', api_views.api_request_access, name='api_request_access'),
    path('access/approve/', api_views.api_approve_access, name='api_approve_access'),
    path('access/pending/', api_views.api_pending_requests, name='api_pending_requests'),
    path('access/check/<path:service_url>/', api_views.api_check_service_access, name='api_check_service_access'),
    
    # Documentation endpoints
    path('docs/', documentation_views.APIDocumentationView.as_view(), name='api_docs'),
    path('schema/', documentation_views.APISchemaView.as_view(), name='api_schema'),
]
