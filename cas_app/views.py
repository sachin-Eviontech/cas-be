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
    template_name = 'login.html'
    
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
    
    return render(request, 'token_dashboard.html', context)


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
    return redirect('cas:login')


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


from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from .models import AuthenticationLog
from .token_utils import (
    generate_service_tokens, verify_token, validate_service_token,
    check_user_service_access_by_url, get_user_accessible_services_by_token,
    refresh_service_access_token, get_user_attributes_from_token
)
from .utils import get_client_ip
from .serializers import LoginRequestSerializer
import logging

logger = logging.getLogger('cas_app')


@api_view(['POST'])
@permission_classes([])
def token_login(request):
    """
    Service-specific login and get JWT tokens
    Service parameter is REQUIRED
    """
    serializer = LoginRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    username = serializer.validated_data['username']
    password = serializer.validated_data['password']
    service_url = serializer.validated_data.get('service')
    remember_me = serializer.validated_data.get('remember_me', False)
    
    # Service parameter is mandatory
    if not service_url:
        return Response({
            'success': False,
            'message': 'Service parameter is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(request, username=username, password=password)
    if user is not None and user.is_active:
        # Check if user has access to the requested service BEFORE generating tokens
        has_access, access_message, service = check_user_service_access_by_url(user, service_url)
        if not has_access:
            # Log failed access attempt
            AuthenticationLog.objects.create(
                user=user,
                action='token_login_access_denied',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                details=f'{{"service": "{service_url}", "reason": "{access_message}"}}'
            )
            
            return Response({
                'success': False,
                'message': f'Access denied to service: {access_message}',
                'service_url': service_url
            }, status=status.HTTP_403_FORBIDDEN)
        
        login(request, user)
        
        # Generate service-specific JWT tokens
        access_token, refresh_token = generate_service_tokens(user, service)
        
        # Log successful authentication
        AuthenticationLog.objects.create(
            user=user,
            service=service,
            action='token_login',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        response_data = {
            'success': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': 3600,  # 1 hour
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            },
            'service': {
                'id': service.id,
                'name': service.name,
                'url': service.url,
                'description': service.description
            },
            'message': 'Login successful and tokens generated for service'
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        # Log failed authentication
        AuthenticationLog.objects.create(
            action='token_login',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=False,
            details='{"username": "' + username + '", "service": "' + (service_url or 'none') + '"}'
        )
        
        return Response({
            'success': False,
            'message': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([])
def token_refresh(request):
    """
    Refresh service-specific access token using refresh token
    """
    refresh_token = request.data.get('refresh_token')
    if not refresh_token:
        return Response({
            'success': False,
            'message': 'Refresh token is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    access_token, message = refresh_service_access_token(refresh_token)
    if access_token:
        # Get service info from the new token for response
        payload = verify_token(access_token)
        service_info = {
            'id': payload.get('service_id'),
            'name': payload.get('service_name'),
            'url': payload.get('service_url')
        }
        
        return Response({
            'success': True,
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'service': service_info,
            'message': message
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'success': False,
            'message': message
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def token_logout(request):
    """
    Logout and invalidate tokens (client-side token removal)
    """
    # Log logout
    AuthenticationLog.objects.create(
        user=request.user,
        action='token_logout',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        success=True
    )
    
    logout(request)
    
    return Response({
        'success': True,
        'message': 'Logout successful'
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([])
def token_validate(request):
    """
    Validate service-specific token
    Both token and service parameters are REQUIRED
    """
    token = request.data.get('token')
    service_url = request.data.get('service')
    
    if not token:
        return Response({
            'success': False,
            'message': 'Token is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if not service_url:
        return Response({
            'success': False,
            'message': 'Service parameter is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Validate service-specific token
    is_valid, user, service, message = validate_service_token(token, service_url)
    
    if not is_valid:
        # Log failed validation
        AuthenticationLog.objects.create(
            user=user,  # May be None if token is completely invalid
            action='token_validate_failed',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=False,
            details=f'{{"service": "{service_url}", "reason": "{message}"}}'
        )
        
        return Response({
            'success': False,
            'message': message,
            'service_url': service_url
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    # Log successful validation
    AuthenticationLog.objects.create(
        user=user,
        service=service,
        action='token_validate',
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
            'is_active': user.is_active
        },
        'message': message
    }
    
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([])
def token_user_info(request):
    """
    Get user information from service-specific token
    Both token and service parameters are REQUIRED
    """
    token = request.data.get('token')
    service_url = request.data.get('service')
    
    if not token:
        return Response({
            'success': False,
            'message': 'Token is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if not service_url:
        return Response({
            'success': False,
            'message': 'Service parameter is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Validate service-specific token
    is_valid, user, service, message = validate_service_token(token, service_url)
    
    if not is_valid:
        return Response({
            'success': False,
            'message': message
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_active': user.is_active
        },
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
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([])
def get_user_services(request):
    """
    Get all services that a user has access to
    Requires valid credentials (not token-based)
    """
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({
            'success': False,
            'message': 'Username and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(request, username=username, password=password)
    if not user or not user.is_active:
        return Response({
            'success': False,
            'message': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    # Get accessible services using the token utility
    accessible_services = get_user_accessible_services_by_token(None, user=user)
    
    services_data = []
    for service_info in accessible_services:
        service_data = {
            'id': service_info['service'].id,
            'name': service_info['service'].name,
            'url': service_info['service'].url,
            'description': service_info['service'].description,
            'access_type': service_info['access_type'],
            'access_method': service_info['access_method'],
            'granted_at': service_info['granted_at'].isoformat() if service_info['granted_at'] else None,
            'expires_at': service_info['expires_at'].isoformat() if service_info['expires_at'] else None
        }
        if 'group_name' in service_info:
            service_data['group_name'] = service_info['group_name']
        services_data.append(service_data)
    
    return Response({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        },
        'accessible_services': services_data,
        'count': len(services_data)
    }, status=status.HTTP_200_OK)



def logout_view(request):
    logout(request)
    return redirect('cas:login')