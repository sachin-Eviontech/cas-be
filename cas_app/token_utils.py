import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from .models import UserServiceAccess, ServiceGroup, UserGroupAccess, Service
import logging

logger = logging.getLogger('cas_app')

# JWT Settings
JWT_SECRET_KEY = getattr(settings, 'JWT_SECRET_KEY', 'your-secret-key-change-this')
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_LIFETIME = getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME', 60 * 60)  # 1 hour
JWT_REFRESH_TOKEN_LIFETIME = getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', 7 * 24 * 60 * 60)  # 7 days


def generate_service_tokens(user, service):
    """
    Generate service-specific access and refresh tokens for a user
    
    Args:
        user: User object
        service: Service object
        
    Returns:
        tuple: (access_token, refresh_token)
    """
    now = datetime.utcnow()
    
    # Access token payload - service-specific
    access_payload = {
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'service_id': service.id,
        'service_name': service.name,
        'service_url': service.url,
        'token_type': 'access',
        'iat': now,
        'exp': now + timedelta(seconds=JWT_ACCESS_TOKEN_LIFETIME)
    }
    
    # Refresh token payload - service-specific
    refresh_payload = {
        'user_id': user.id,
        'username': user.username,
        'service_id': service.id,
        'service_name': service.name,
        'service_url': service.url,
        'token_type': 'refresh',
        'iat': now,
        'exp': now + timedelta(seconds=JWT_REFRESH_TOKEN_LIFETIME)
    }
    
    access_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    return access_token, refresh_token


def verify_token(token):
    """
    Verify and decode a JWT token
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return None


def get_user_from_token(token):
    """
    Get user object from JWT token
    """
    payload = verify_token(token)
    if not payload:
        return None
    
    try:
        user = User.objects.get(id=payload['user_id'], is_active=True)
        return user
    except User.DoesNotExist:
        logger.warning(f"User {payload.get('user_id')} not found or inactive")
        return None


def validate_service_token(token, required_service_url):
    """
    Validate a service-specific token and check if it matches the required service
    
    Args:
        token: JWT token to validate
        required_service_url: The service URL that the token should be valid for
        
    Returns:
        tuple: (is_valid, user_object, service_object, message)
    """
    # Verify token structure
    payload = verify_token(token)
    if not payload:
        return False, None, None, "Invalid or expired token"
    
    # Check if token has service information
    token_service_url = payload.get('service_url')
    token_service_id = payload.get('service_id')
    
    if not token_service_url or not token_service_id:
        return False, None, None, "Token is not service-specific"
    
    # Check if token is for the required service
    if token_service_url != required_service_url:
        return False, None, None, f"Token is for different service: {token_service_url}"
    
    # Get user from token
    try:
        user = User.objects.get(id=payload['user_id'], is_active=True)
    except User.DoesNotExist:
        return False, None, None, "User not found or inactive"
    
    # Get service from token
    try:
        service = Service.objects.get(id=token_service_id, url=required_service_url, is_active=True)
    except Service.DoesNotExist:
        return False, None, None, "Service not found or inactive"
    
    # Check if user still has access to this service
    has_access, access_message = check_user_service_access(user, service)
    if not has_access:
        return False, user, service, f"Access revoked: {access_message}"
    
    return True, user, service, "Token valid and access granted"


def check_user_service_access(user, service):
    """
    Check if user has access to a specific service object
    
    Args:
        user: User object
        service: Service object
        
    Returns:
        tuple: (has_access, message)
    """
    # Check direct service access
    try:
        access = UserServiceAccess.objects.get(user=user, service=service, is_active=True)
        if access.can_access():
            return True, "Access granted"
        else:
            return False, f"Access denied: {access.access_type}"
    except UserServiceAccess.DoesNotExist:
        pass
    
    # Check group access
    for group_access in UserGroupAccess.objects.filter(user=user, is_active=True):
        if group_access.can_access():
            if service in group_access.service_group.services.all():
                return True, "Access granted via group"
    
    return False, "No access permission found"


def check_user_service_access_by_url(user, service_url):
    """
    Check if user has access to a service by URL
    
    Args:
        user: User object
        service_url: Service URL string
        
    Returns:
        tuple: (has_access, message, service_object)
    """
    try:
        service = Service.objects.get(url=service_url, is_active=True)
    except Service.DoesNotExist:
        return False, "Service not found or inactive", None
    
    has_access, message = check_user_service_access(user, service)
    return has_access, message, service


def get_user_accessible_services_by_token(token, user=None):
    """
    Get all services that user (from token or provided user) has access to
    """
    if user is None:
        user = get_user_from_token(token)
        if not user:
            return []
    
    accessible_services = []
    
    # Direct service access
    for access in UserServiceAccess.objects.filter(user=user, is_active=True):
        if access.can_access():
            accessible_services.append({
                'service': access.service,
                'access_type': access.access_type,
                'granted_at': access.granted_at,
                'expires_at': access.expires_at,
                'access_method': 'direct'
            })
    
    # Group access
    for group_access in UserGroupAccess.objects.filter(user=user, is_active=True):
        if group_access.can_access():
            for service in group_access.service_group.services.filter(is_active=True):
                # Avoid duplicates
                if not any(s['service'].id == service.id for s in accessible_services):
                    accessible_services.append({
                        'service': service,
                        'access_type': group_access.access_type,
                        'granted_at': group_access.granted_at,
                        'expires_at': group_access.expires_at,
                        'access_method': 'group',
                        'group_name': group_access.service_group.name
                    })
    
    return accessible_services


def refresh_service_access_token(refresh_token):
    """
    Generate new service-specific access token from refresh token
    
    Args:
        refresh_token: JWT refresh token
        
    Returns:
        str or None: New access token or None if invalid
    """
    payload = verify_token(refresh_token)
    if not payload or payload.get('token_type') != 'refresh':
        return None, "Invalid refresh token"
    
    # Check if refresh token has service information
    service_id = payload.get('service_id')
    service_url = payload.get('service_url')
    
    if not service_id or not service_url:
        return None, "Refresh token is not service-specific"
    
    try:
        user = User.objects.get(id=payload['user_id'], is_active=True)
        service = Service.objects.get(id=service_id, url=service_url, is_active=True)
        
        # Check if user still has access to the service
        has_access, access_message = check_user_service_access(user, service)
        if not has_access:
            return None, f"Access revoked: {access_message}"
        
        # Generate new access token
        access_token, _ = generate_service_tokens(user, service)
        return access_token, "Token refreshed successfully"
        
    except (User.DoesNotExist, Service.DoesNotExist):
        return None, "User or service not found"


def get_user_attributes_from_token(token):
    """
    Get user attributes from token
    """
    user = get_user_from_token(token)
    if not user:
        return {}
    
    return {
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_active': user.is_active,
        'date_joined': user.date_joined.isoformat() if user.date_joined else None
    }
