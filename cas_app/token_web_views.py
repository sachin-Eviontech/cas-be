from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView
from .models import AuthenticationLog, UserProfile
from .token_utils import generate_service_tokens, check_user_service_access_by_url
from .utils import get_client_ip, check_user_service_access
import json
import logging

logger = logging.getLogger('cas_app')


class TokenLoginView(TemplateView):
    """Token-based login page"""
    template_name = 'cas/token_login.html'
    
    def get(self, request, *args, **kwargs):
        service_url = request.GET.get('service', '')
        
        # Service parameter is mandatory for token-based login
        if not service_url:
            messages.error(request, 'Service parameter is required for token-based login')
            return render(request, self.template_name, {
                'service': service_url,
                'next': request.GET.get('next', ''),
                'error': 'Service parameter is required'
            })
        
        if request.user.is_authenticated:
            # Check service access and redirect with token
            has_access, access_message, service = check_user_service_access_by_url(request.user, service_url)
            if has_access:
                # Generate service-specific tokens
                access_token, refresh_token = generate_service_tokens(request.user, service)
                return redirect(f"{service_url}?token={access_token}")
            else:
                messages.error(request, f'Access denied: {access_message}')
                return render(request, self.template_name, {'service': service_url})
        
        return render(request, self.template_name, {
            'service': service_url,
            'next': request.GET.get('next', '')
        })
    
    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        service_url = request.POST.get('service', '')
        remember_me = request.POST.get('remember_me', False)
        
        if not username or not password:
            messages.error(request, 'Username and password are required.')
            return render(request, self.template_name, {'service': service_url})
        
        # Service parameter is mandatory
        if not service_url:
            messages.error(request, 'Service parameter is required.')
            return render(request, self.template_name, {'service': service_url})
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active:
                # Check service access BEFORE login
                has_access, access_message, service = check_user_service_access_by_url(user, service_url)
                if not has_access:
                    # Log failed access attempt
                    AuthenticationLog.objects.create(
                        user=user,
                        action='token_web_login_access_denied',
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        details=f'{{"service": "{service_url}", "reason": "{access_message}"}}'
                    )
                    messages.error(request, f'Access denied: {access_message}')
                    return render(request, self.template_name, {'service': service_url})
                
                login(request, user)
                
                # Log successful authentication
                AuthenticationLog.objects.create(
                    user=user,
                    service=service,
                    action='token_web_login',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=True
                )
                
                # Generate service-specific token and redirect
                access_token, refresh_token = generate_service_tokens(user, service)
                return redirect(f"{service_url}?token={access_token}")
            else:
                messages.error(request, 'Account is disabled.')
        else:
            # Log failed authentication
            AuthenticationLog.objects.create(
                action='token_web_login',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                details='{"username": "' + username + '", "service": "' + service_url + '"}'
            )
            messages.error(request, 'Invalid username or password.')
        
        return render(request, self.template_name, {'service': service_url})


@login_required
def token_dashboard(request):
    """Token-based dashboard - shows available services"""
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    # Get accessible services (no tokens needed, just user-based)
    from .token_utils import get_user_accessible_services_by_token
    accessible_services = get_user_accessible_services_by_token(None, user=request.user)
    
    # Get recent authentication logs
    recent_logs = AuthenticationLog.objects.filter(user=request.user).order_by('-created_at')[:10]
    
    context = {
        'user_profile': user_profile,
        'accessible_services': accessible_services,
        'recent_logs': recent_logs,
    }
    
    return render(request, 'cas/token_dashboard.html', context)


@login_required
def token_logout(request):
    """Token-based logout"""
    service = request.GET.get('service', '')
    
    # Log logout
    AuthenticationLog.objects.create(
        user=request.user,
        action='token_web_logout',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        success=True
    )
    
    logout(request)
    
    if service:
        return redirect(service)
    return redirect('cas:token_login')


@csrf_exempt
@require_http_methods(["GET", "POST"])
def token_validate_web(request):
    """Service-specific token validation endpoint for web services"""
    if request.method == 'GET':
        token = request.GET.get('token')
        service_url = request.GET.get('service')
    else:
        try:
            data = json.loads(request.body)
            token = data.get('token')
            service_url = data.get('service')
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            }, status=400)
    
    if not token:
        return JsonResponse({
            'success': False,
            'error': 'Token parameter is required'
        }, status=400)
    
    if not service_url:
        return JsonResponse({
            'success': False,
            'error': 'Service parameter is required'
        }, status=400)
    
    from .token_utils import validate_service_token
    
    # Validate service-specific token
    is_valid, user, service, message = validate_service_token(token, service_url)
    
    if not is_valid:
        # Log failed validation
        AuthenticationLog.objects.create(
            user=user,  # May be None if token is completely invalid
            action='token_web_validate_failed',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=False,
            details=f'{{"service": "{service_url}", "reason": "{message}"}}'
        )
        
        return JsonResponse({
            'success': False,
            'error': message,
            'service_url': service_url
        }, status=401)
    
    # Log successful validation
    AuthenticationLog.objects.create(
        user=user,
        service=service,
        action='token_web_validate',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        success=True
    )
    
    response_data = {
        'success': True,
        'user': user.username,
        'service': {
            'id': service.id,
            'name': service.name,
            'url': service.url,
            'description': service.description
        },
        'attributes': {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_active': user.is_active,
            'date_joined': user.date_joined.isoformat() if user.date_joined else None
        }
    }
    
    return JsonResponse(response_data)
