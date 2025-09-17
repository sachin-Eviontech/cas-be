from django.urls import path
from . import views
from . import token_web_views

app_name = 'cas'

urlpatterns = [
    # Root CAS URL - redirect to login or dashboard
    path('', views.cas_root, name='root'),
    
    # CAS Protocol URLs
    path('login/', views.CASLoginView.as_view(), name='login'),
    path('logout/', views.cas_logout, name='logout'),
    path('serviceValidate/', views.cas_service_validate, name='service_validate'),
    path('validate/', views.cas_validate, name='validate'),
    path('proxyValidate/', views.cas_proxy_validate, name='proxy_validate'),
    
    # Dashboard
    path('dashboard/', views.cas_dashboard, name='dashboard'),
    
    # Token-based URLs
    path('token/', token_web_views.TokenLoginView.as_view(), name='token_login'),
    path('token/dashboard/', token_web_views.token_dashboard, name='token_dashboard'),
    path('token/logout/', token_web_views.token_logout, name='token_logout'),
    path('token/validate/', token_web_views.token_validate_web, name='token_validate_web'),
]
