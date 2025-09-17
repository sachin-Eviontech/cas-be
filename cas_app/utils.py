import re
from urllib.parse import urlparse
from django.conf import settings
from django.utils import timezone


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def generate_ticket_id(ticket_type='ST'):
    """Generate a unique ticket ID"""
    import uuid
    return f"{ticket_type}-{uuid.uuid4().hex}"


def validate_service_url(service_url):
    """Validate if service URL is registered and active"""
    if not service_url:
        return False
    
    try:
        # Parse URL to check format
        parsed = urlparse(service_url)
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Check if service is registered
        from .models import Service
        service = Service.objects.filter(url=service_url, is_active=True).first()
        return service is not None
        
    except Exception:
        return False


def is_valid_redirect_url(url):
    """Check if redirect URL is safe"""
    if not url:
        return False
    
    try:
        parsed = urlparse(url)
        # Only allow http and https schemes
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Check against allowed hosts
        allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])
        if '*' not in allowed_hosts and parsed.netloc not in allowed_hosts:
            return False
        
        return True
        
    except Exception:
        return False


def clean_username(username):
    """Clean and validate username"""
    if not username:
        return None
    
    # Remove any whitespace
    username = username.strip()
    
    # Check length
    if len(username) < 3 or len(username) > 150:
        return None
    
    # Check for valid characters (alphanumeric, underscore, hyphen, dot)
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return None
    
    return username


def format_cas_error(error_code, error_message):
    """Format CAS error response"""
    return {
        'error': error_message,
        'error_code': error_code
    }


def get_user_attributes(user):
    """Get user attributes for CAS response"""
    try:
        profile = user.userprofile
        attributes = {
            'username': user.username,
            'email': user.email or '',
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'is_active': user.is_active,
            'date_joined': user.date_joined.isoformat(),
        }
        
        # Add profile attributes if available
        if profile:
            if profile.phone_number:
                attributes['phone_number'] = profile.phone_number
            if profile.department:
                attributes['department'] = profile.department
            if profile.employee_id:
                attributes['employee_id'] = profile.employee_id
            attributes['is_cas_admin'] = profile.is_cas_admin
        
        return attributes
        
    except Exception:
        # Fallback to basic attributes
        return {
            'username': user.username,
            'email': user.email or '',
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'is_active': user.is_active,
        }


def check_user_service_access(user, service_url):
    """Check if user has access to a specific service"""
    from .models import Service, UserServiceAccess, ServiceGroup, UserGroupAccess
    
    try:
        # Get the service object
        service = Service.objects.filter(url=service_url, is_active=True).first()
        if not service:
            return False, "Service not found or inactive"
        
        # Check direct service access
        service_access = UserServiceAccess.objects.filter(
            user=user, 
            service=service, 
            is_active=True
        ).first()
        
        if service_access:
            if service_access.access_type == 'DENY':
                return False, "Access denied to this service"
            elif service_access.access_type == 'ALLOW':
                if service_access.is_expired():
                    return False, "Access has expired"
                return True, "Access granted"
            elif service_access.access_type == 'PENDING':
                return False, "Access request pending approval"
        
        # Check group access
        service_groups = ServiceGroup.objects.filter(services=service, is_active=True)
        for group in service_groups:
            group_access = UserGroupAccess.objects.filter(
                user=user,
                service_group=group,
                is_active=True
            ).first()
            
            if group_access:
                if group_access.access_type == 'DENY':
                    return False, "Access denied to service group"
                elif group_access.access_type == 'ALLOW':
                    if group_access.is_expired():
                        return False, "Group access has expired"
                    return True, "Access granted via service group"
                elif group_access.access_type == 'PENDING':
                    return False, "Group access request pending approval"
        
        # If no specific access rules, check if user is CAS admin
        try:
            profile = user.userprofile
            if profile.is_cas_admin:
                return True, "Access granted (CAS admin)"
        except:
            pass
        
        # Default: no access
        return False, "No access granted to this service"
        
    except Exception as e:
        return False, f"Error checking access: {str(e)}"


def get_user_accessible_services(user):
    """Get all services that user has access to"""
    from .models import Service, UserServiceAccess, ServiceGroup, UserGroupAccess
    
    accessible_services = []
    
    try:
        # Get direct service access
        direct_access = UserServiceAccess.objects.filter(
            user=user,
            access_type='ALLOW',
            is_active=True
        ).exclude(expires_at__lt=timezone.now())
        
        for access in direct_access:
            if not access.is_expired():
                accessible_services.append({
                    'service': access.service,
                    'access_type': 'direct',
                    'granted_at': access.granted_at,
                    'expires_at': access.expires_at
                })
        
        # Get group access
        group_access = UserGroupAccess.objects.filter(
            user=user,
            access_type='ALLOW',
            is_active=True
        ).exclude(expires_at__lt=timezone.now())
        
        for access in group_access:
            if not access.is_expired():
                for service in access.service_group.services.filter(is_active=True):
                    # Avoid duplicates
                    if not any(s['service'].id == service.id for s in accessible_services):
                        accessible_services.append({
                            'service': service,
                            'access_type': 'group',
                            'group_name': access.service_group.name,
                            'granted_at': access.granted_at,
                            'expires_at': access.expires_at
                        })
        
        # If user is CAS admin, add all active services
        try:
            profile = user.userprofile
            if profile.is_cas_admin:
                all_services = Service.objects.filter(is_active=True)
                for service in all_services:
                    if not any(s['service'].id == service.id for s in accessible_services):
                        accessible_services.append({
                            'service': service,
                            'access_type': 'admin',
                            'granted_at': None,
                            'expires_at': None
                        })
        except:
            pass
        
        return accessible_services
        
    except Exception as e:
        return []


def request_service_access(user, service_id=None, service_group_id=None, reason=""):
    """Request access to a service or service group"""
    from .models import Service, ServiceGroup, UserServiceAccess, UserGroupAccess
    
    try:
        if service_id:
            service = Service.objects.get(id=service_id, is_active=True)
            access, created = UserServiceAccess.objects.get_or_create(
                user=user,
                service=service,
                defaults={
                    'access_type': 'PENDING',
                    'reason': reason,
                    'is_active': True
                }
            )
            return access, created, "Service access request created"
        
        elif service_group_id:
            service_group = ServiceGroup.objects.get(id=service_group_id, is_active=True)
            access, created = UserGroupAccess.objects.get_or_create(
                user=user,
                service_group=service_group,
                defaults={
                    'access_type': 'PENDING',
                    'reason': reason,
                    'is_active': True
                }
            )
            return access, created, "Service group access request created"
        
        return None, False, "Invalid request parameters"
        
    except Exception as e:
        return None, False, f"Error creating access request: {str(e)}"
