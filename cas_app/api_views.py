from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from datetime import timedelta
from .models import (
    Service, Ticket, ProxyGrantingTicket, AuthenticationLog, UserProfile,
    UserServiceAccess, ServiceGroup, UserGroupAccess
)
from .serializers import (
    UserSerializer, UserProfileSerializer, ServiceSerializer, 
    TicketSerializer, ProxyGrantingTicketSerializer, AuthenticationLogSerializer,
    LoginRequestSerializer, LogoutRequestSerializer, ValidateRequestSerializer,
    UserServiceAccessSerializer, ServiceGroupSerializer, UserGroupAccessSerializer,
    AccessRequestSerializer, AccessApprovalSerializer
)
from .utils import (
    get_client_ip, validate_service_url, get_user_attributes,
    check_user_service_access, get_user_accessible_services, request_service_access
)
import logging

logger = logging.getLogger('cas_app')


@api_view(['GET'])
@permission_classes([])
def api_root(request):
    """Root API endpoint - provides API documentation and available endpoints"""
    base_url = request.build_absolute_uri('/api/')
    
    endpoints = {
        'authentication': {
            'login': f'{base_url}auth/login/',
            'logout': f'{base_url}auth/logout/',
            'validate': f'{base_url}auth/validate/',
            'user_info': f'{base_url}auth/user/',
        },
        'service_token_authentication': {
            'login': f'{base_url}token/login/',
            'refresh': f'{base_url}token/refresh/',
            'logout': f'{base_url}token/logout/',
            'validate': f'{base_url}token/validate/',
            'user_info': f'{base_url}token/user/',
            'user_services': f'{base_url}user/services/',
        },
        'services': {
            'list_create': f'{base_url}services/',
            'detail': f'{base_url}services/<id>/',
        },
        'user_data': {
            'tickets': f'{base_url}tickets/',
            'logs': f'{base_url}logs/',
            'profile': f'{base_url}profile/',
        },
        'admin': {
            'stats': f'{base_url}admin/stats/',
        }
    }
    
    return Response({
        'message': 'CAS Server API',
        'version': '1.0',
        'description': 'Central Authentication Service API endpoints',
        'endpoints': endpoints,
        'documentation': {
            'authentication': 'POST endpoints for login/logout and ticket validation',
            'service_token_authentication': 'Service-specific JWT token authentication (recommended)',
            'services': 'CRUD operations for registered services (admin only)',
            'user_data': 'User-specific data endpoints (authenticated users)',
            'admin': 'Administrative endpoints (admin users only)'
        }
    }, status=status.HTTP_200_OK)


class ServiceListCreateView(generics.ListCreateAPIView):
    """List and create services"""
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAdminUser]


class ServiceDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a service"""
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAdminUser]

    
class TicketListView(generics.ListAPIView):
    """List tickets for authenticated user"""
    serializer_class = TicketSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Ticket.objects.filter(user=self.request.user).order_by('-created_at')


class AuthenticationLogListView(generics.ListAPIView):
    """List authentication logs for authenticated user"""
    serializer_class = AuthenticationLogSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return AuthenticationLog.objects.filter(user=self.request.user).order_by('-created_at')


class UserProfileView(generics.RetrieveUpdateAPIView):
    """Retrieve and update user profile"""
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile


@api_view(['POST'])
@permission_classes([])
def api_login(request):
    """API login endpoint"""
    serializer = LoginRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    username = serializer.validated_data['username']
    password = serializer.validated_data['password']
    service_url = serializer.validated_data.get('service')
    remember_me = serializer.validated_data.get('remember_me', False)
    
    user = authenticate(request, username=username, password=password)
    if user is not None and user.is_active:
        login(request, user)
        
        # Generate or get existing token for the user
        token, created = Token.objects.get_or_create(user=user)
        
        # Log authentication
        AuthenticationLog.objects.create(
            user=user,
            action='api_login',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        response_data = {
            'success': True,
            'user': UserSerializer(user).data,
            'token': token.key,
            'message': 'Login successful'
        }
        
        # Generate service ticket if service provided
        if service_url and validate_service_url(service_url):
            service_obj = Service.objects.filter(url=service_url, is_active=True).first()
            if service_obj:
                ticket = Ticket.objects.create(
                    ticket_type='ST',
                    user=user,
                    service=service_obj,
                    expires_at=timezone.now() + timedelta(minutes=5)
                )
                response_data['ticket'] = ticket.ticket_id
                response_data['service'] = service_url
        
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        # Log failed authentication
        AuthenticationLog.objects.create(
            action='api_login',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=False,
            details='{"username": "' + username + '"}'
        )
        
        return Response({
            'success': False,
            'message': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout(request):
    """API logout endpoint"""
    # Log logout
    AuthenticationLog.objects.create(
        user=request.user,
        action='api_logout',
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
def api_validate(request):
    """API ticket validation endpoint"""
    serializer = ValidateRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    ticket_id = serializer.validated_data['ticket']
    service_url = serializer.validated_data['service']
    pgt_url = serializer.validated_data.get('pgtUrl')
    
    try:
        ticket_obj = Ticket.objects.get(ticket_id=ticket_id, is_valid=True)
        
        # Check if ticket is expired
        if ticket_obj.is_expired():
            ticket_obj.is_valid = False
            ticket_obj.save()
            return Response({
                'success': False,
                'error': 'ticket has expired'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if ticket is already used
        if ticket_obj.is_used:
            return Response({
                'success': False,
                'error': 'ticket has already been used'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate service
        if not validate_service_url(service_url):
            return Response({
                'success': False,
                'error': 'invalid service URL'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Mark ticket as used
        ticket_obj.is_used = True
        ticket_obj.save()
        
        # Log validation
        AuthenticationLog.objects.create(
            user=ticket_obj.user,
            service=ticket_obj.service,
            action='api_validate',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        response_data = {
            'success': True,
            'user': ticket_obj.user.username,
            'attributes': get_user_attributes(ticket_obj.user)
        }
        
        # Handle PGT if provided
        if pgt_url:
            pgt = ProxyGrantingTicket.objects.create(
                user=ticket_obj.user,
                expires_at=timezone.now() + timedelta(hours=2)
            )
            response_data['pgt'] = pgt.pgt_id
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Ticket.DoesNotExist:
        return Response({
            'success': False,
            'error': 'invalid ticket'
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Error validating ticket: {str(e)}")
        return Response({
            'success': False,
            'error': 'internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_user_info(request):
    """Get current user information"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    return Response({
        'user': UserSerializer(request.user).data,
        'profile': UserProfileSerializer(profile).data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_stats(request):
    """Get CAS server statistics (admin only)"""
    stats = {
        'total_users': User.objects.count(),
        'active_users': User.objects.filter(is_active=True).count(),
        'total_services': Service.objects.count(),
        'active_services': Service.objects.filter(is_active=True).count(),
        'total_tickets': Ticket.objects.count(),
        'valid_tickets': Ticket.objects.filter(is_valid=True, is_used=False).count(),
        'recent_logins': AuthenticationLog.objects.filter(
            action='login', 
            success=True,
            created_at__gte=timezone.now() - timedelta(days=7)
        ).count(),
    }
    
    return Response(stats, status=status.HTTP_200_OK)


# Access Management API Views

class ServiceGroupListCreateView(generics.ListCreateAPIView):
    """List and create service groups"""
    queryset = ServiceGroup.objects.all()
    serializer_class = ServiceGroupSerializer
    permission_classes = [IsAdminUser]


class ServiceGroupDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a service group"""
    queryset = ServiceGroup.objects.all()
    serializer_class = ServiceGroupSerializer
    permission_classes = [IsAdminUser]


class UserServiceAccessListView(generics.ListAPIView):
    """List user's service access permissions"""
    serializer_class = UserServiceAccessSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return UserServiceAccess.objects.filter(user=self.request.user).order_by('-created_at')


class UserGroupAccessListView(generics.ListAPIView):
    """List user's group access permissions"""
    serializer_class = UserGroupAccessSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return UserGroupAccess.objects.filter(user=self.request.user).order_by('-created_at')


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_accessible_services(request):
    """Get all services that user has access to"""
    accessible_services = get_user_accessible_services(request.user)
    
    services_data = []
    for service_info in accessible_services:
        service_data = ServiceSerializer(service_info['service']).data
        service_data['access_type'] = service_info['access_type']
        service_data['granted_at'] = service_info['granted_at']
        service_data['expires_at'] = service_info['expires_at']
        if 'group_name' in service_info:
            service_data['group_name'] = service_info['group_name']
        services_data.append(service_data)
    
    return Response({
        'accessible_services': services_data,
        'count': len(services_data)
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_request_access(request):
    """Request access to a service or service group"""
    serializer = AccessRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    service_id = serializer.validated_data.get('service_id')
    service_group_id = serializer.validated_data.get('service_group_id')
    reason = serializer.validated_data.get('reason', '')
    
    access, created, message = request_service_access(
        request.user, service_id, service_group_id, reason
    )
    
    if access:
        if created:
            return Response({
                'success': True,
                'message': message,
                'access_id': access.id
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'success': False,
                'message': 'Access request already exists'
            }, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({
            'success': False,
            'message': message
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def api_approve_access(request):
    """Approve or deny access requests (admin only)"""
    serializer = AccessApprovalSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    access_id = serializer.validated_data['access_id']
    access_type = serializer.validated_data['access_type']
    reason = serializer.validated_data.get('reason', '')
    expires_at = serializer.validated_data.get('expires_at')
    
    try:
        # Try to find in UserServiceAccess first
        try:
            access = UserServiceAccess.objects.get(id=access_id)
        except UserServiceAccess.DoesNotExist:
            # Try UserGroupAccess
            access = UserGroupAccess.objects.get(id=access_id)
        
        access.access_type = access_type
        access.granted_by = request.user
        access.granted_at = timezone.now()
        access.reason = reason
        if expires_at:
            access.expires_at = expires_at
        
        access.save()
        
        return Response({
            'success': True,
            'message': f'Access {access_type.lower()}ed successfully',
            'access': {
                'id': access.id,
                'user': access.user.username,
                'access_type': access.access_type,
                'granted_at': access.granted_at,
                'expires_at': access.expires_at
            }
        }, status=status.HTTP_200_OK)
        
    except (UserServiceAccess.DoesNotExist, UserGroupAccess.DoesNotExist):
        return Response({
            'success': False,
            'message': 'Access request not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error approving access: {str(e)}")
        return Response({
            'success': False,
            'message': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_pending_requests(request):
    """Get all pending access requests (admin only)"""
    service_requests = UserServiceAccess.objects.filter(
        access_type='PENDING',
        is_active=True
    ).order_by('-created_at')
    
    group_requests = UserGroupAccess.objects.filter(
        access_type='PENDING',
        is_active=True
    ).order_by('-created_at')
    
    service_data = UserServiceAccessSerializer(service_requests, many=True).data
    group_data = UserGroupAccessSerializer(group_requests, many=True).data
    
    return Response({
        'service_requests': service_data,
        'group_requests': group_data,
        'total_pending': len(service_data) + len(group_data)
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_check_service_access(request, service_url):
    """Check if user has access to a specific service"""
    has_access, message = check_user_service_access(request.user, service_url)
    
    return Response({
        'has_access': has_access,
        'message': message,
        'service_url': service_url
    }, status=status.HTTP_200_OK)
