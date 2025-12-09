from django.urls import path
from .views import*


app_name = 'cas'

urlpatterns = [
    # Token-based URLs
    path('dashboard/', token_dashboard, name='dashboard'),
    path('login/', TokenLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('validate/', token_validate_web, name='validate_web'),
]

