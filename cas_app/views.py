from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
from django.urls import reverse
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView
from django.core.exceptions import ObjectDoesNotExist
import json
import logging
from datetime import timedelta
from .models import (
    Service, Ticket, ProxyGrantingTicket, AuthenticationLog, UserProfile,
    UserServiceAccess, ServiceGroup, UserGroupAccess
)
from .utils import (
    get_client_ip, generate_ticket_id, validate_service_url,
    check_user_service_access, get_user_accessible_services
)

logger = logging.getLogger('cas_app')


def cas_root(request):
    """Root CAS URL - redirect to login or dashboard based on authentication status"""
    if request.user.is_authenticated:
        return redirect('cas:dashboard')
    else:
        return redirect('cas:login')


class CASLoginView(TemplateView):
    """CAS Login page"""
    template_name = 'cas/login.html'
    
    def get(self, request, *args, **kwargs):
        service = request.GET.get('service', '')
        if service and not validate_service_url(service):
            return render(request, 'cas/error.html', {
                'error': 'Invalid service URL',
                'service': service
            })
        
        if request.user.is_authenticated:
            if service:
                return redirect(f"{settings.CAS_LOGIN_URL}?service={service}")
            return redirect('cas:dashboard')
        
        return render(request, self.template_name, {
            'service': service,
            'next': request.GET.get('next', '')
        })
    
    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        service = request.POST.get('service', '')
        remember_me = request.POST.get('remember_me', False)
        
        if not username or not password:
            messages.error(request, 'Username and password are required.')
            return render(request, self.template_name, {'service': service})
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                
                # Log authentication
                AuthenticationLog.objects.create(
                    user=user,
                    action='login',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=True
                )
                
                if service:
                    # Check if user has access to this service
                    has_access, access_message = check_user_service_access(user, service)
                    if not has_access:
                        messages.error(request, f'Access denied: {access_message}')
                        return render(request, self.template_name, {'service': service})
                    
                    # Generate service ticket
                    service_obj = Service.objects.filter(url=service, is_active=True).first()
                    if service_obj:
                        ticket = Ticket.objects.create(
                            ticket_type='ST',
                            user=user,
                            service=service_obj,
                            expires_at=timezone.now() + timedelta(minutes=5)
                        )
                        return redirect(f"{service}?ticket={ticket.ticket_id}")
                    else:
                        messages.error(request, 'Service not registered or inactive.')
                        return render(request, self.template_name, {'service': service})
                else:
                    return redirect('cas:dashboard')
            else:
                messages.error(request, 'Account is disabled.')
        else:
            # Log failed authentication
            AuthenticationLog.objects.create(
                action='login',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                details='{"username": "' + username + '"}'
            )
            messages.error(request, 'Invalid username or password.')
        
        return render(request, self.template_name, {'service': service})


@login_required
def cas_logout(request):
    """CAS Logout"""
    service = request.GET.get('service', '')
    
    # Log logout
    AuthenticationLog.objects.create(
        user=request.user,
        action='logout',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        success=True
    )
    
    logout(request)
    
    if service:
        return redirect(service)
    return redirect('cas:login')


@login_required
def cas_dashboard(request):
    """CAS Dashboard for authenticated users"""
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    # Get recent tickets
    recent_tickets = Ticket.objects.filter(user=request.user).order_by('-created_at')[:10]
    
    # Get recent authentication logs
    recent_logs = AuthenticationLog.objects.filter(user=request.user).order_by('-created_at')[:10]
    
    # Get accessible services
    accessible_services = get_user_accessible_services(request.user)
    
    # Get pending access requests
    pending_requests = UserServiceAccess.objects.filter(
        user=request.user,
        access_type='PENDING',
        is_active=True
    ).order_by('-created_at')
    
    context = {
        'user_profile': user_profile,
        'recent_tickets': recent_tickets,
        'recent_logs': recent_logs,
        'accessible_services': accessible_services,
        'pending_requests': pending_requests,
    }
    
    return render(request, 'cas/dashboard.html', context)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def cas_validate(request):
    """CAS Service Validation endpoint"""
    if request.method == 'GET':
        ticket = request.GET.get('ticket')
        service = request.GET.get('service')
        pgt_url = request.GET.get('pgtUrl')
    else:
        data = json.loads(request.body)
        ticket = data.get('ticket')
        service = data.get('service')
        pgt_url = data.get('pgtUrl')
    
    if not ticket or not service:
        return JsonResponse({
            'error': 'ticket and service parameters are required'
        }, status=400)
    
    try:
        ticket_obj = Ticket.objects.get(ticket_id=ticket, is_valid=True)
        
        # Check if ticket is expired
        if ticket_obj.is_expired():
            ticket_obj.is_valid = False
            ticket_obj.save()
            return JsonResponse({
                'error': 'ticket has expired'
            }, status=400)
        
        # Check if ticket is already used
        if ticket_obj.is_used:
            return JsonResponse({
                'error': 'ticket has already been used'
            }, status=400)
        
        # Validate service
        if not validate_service_url(service):
            return JsonResponse({
                'error': 'invalid service URL'
            }, status=400)
        
        # Mark ticket as used
        ticket_obj.is_used = True
        ticket_obj.save()
        
        # Log validation
        AuthenticationLog.objects.create(
            user=ticket_obj.user,
            service=ticket_obj.service,
            action='validate',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        response_data = {
            'success': True,
            'user': ticket_obj.user.username,
            'attributes': {
                'username': ticket_obj.user.username,
                'email': ticket_obj.user.email,
                'first_name': ticket_obj.user.first_name,
                'last_name': ticket_obj.user.last_name,
            }
        }
        
        # Handle PGT if provided
        if pgt_url:
            pgt = ProxyGrantingTicket.objects.create(
                user=ticket_obj.user,
                expires_at=timezone.now() + timedelta(hours=2)
            )
            response_data['pgt'] = pgt.pgt_id
        
        return JsonResponse(response_data)
        
    except Ticket.DoesNotExist:
        return JsonResponse({
            'error': 'invalid ticket'
        }, status=400)
    except Exception as e:
        logger.error(f"Error validating ticket: {str(e)}")
        return JsonResponse({
            'error': 'internal server error'
        }, status=500)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def cas_proxy_validate(request):
    """CAS Proxy Validation endpoint"""
    if request.method == 'GET':
        ticket = request.GET.get('ticket')
        service = request.GET.get('service')
        pgt_url = request.GET.get('pgtUrl')
    else:
        data = json.loads(request.body)
        ticket = data.get('ticket')
        service = data.get('service')
        pgt_url = data.get('pgtUrl')
    
    if not ticket or not service:
        return JsonResponse({
            'error': 'ticket and service parameters are required'
        }, status=400)
    
    try:
        ticket_obj = Ticket.objects.get(ticket_id=ticket, ticket_type='PT', is_valid=True)
        
        # Check if ticket is expired
        if ticket_obj.is_expired():
            ticket_obj.is_valid = False
            ticket_obj.save()
            return JsonResponse({
                'error': 'ticket has expired'
            }, status=400)
        
        # Check if ticket is already used
        if ticket_obj.is_used:
            return JsonResponse({
                'error': 'ticket has already been used'
            }, status=400)
        
        # Validate service
        if not validate_service_url(service):
            return JsonResponse({
                'error': 'invalid service URL'
            }, status=400)
        
        # Mark ticket as used
        ticket_obj.is_used = True
        ticket_obj.save()
        
        # Log validation
        AuthenticationLog.objects.create(
            user=ticket_obj.user,
            service=ticket_obj.service,
            action='proxy_validate',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        response_data = {
            'success': True,
            'user': ticket_obj.user.username,
            'proxies': [],  # Add proxy chain if needed
            'attributes': {
                'username': ticket_obj.user.username,
                'email': ticket_obj.user.email,
                'first_name': ticket_obj.user.first_name,
                'last_name': ticket_obj.user.last_name,
            }
        }
        
        return JsonResponse(response_data)
        
    except Ticket.DoesNotExist:
        return JsonResponse({
            'error': 'invalid ticket'
        }, status=400)
    except Exception as e:
        logger.error(f"Error validating proxy ticket: {str(e)}")
        return JsonResponse({
            'error': 'internal server error'
        }, status=500)


def cas_service_validate(request):
    """CAS Service Validation (XML response)"""
    ticket = request.GET.get('ticket')
    service = request.GET.get('service')
    
    if not ticket or not service:
        return HttpResponse(
            '<?xml version="1.0"?>\n<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">\n'
            '<cas:authenticationFailure code="INVALID_REQUEST">ticket and service parameters are required</cas:authenticationFailure>\n'
            '</cas:serviceResponse>',
            content_type='application/xml'
        )
    
    try:
        ticket_obj = Ticket.objects.get(ticket_id=ticket, is_valid=True)
        
        if ticket_obj.is_expired() or ticket_obj.is_used:
            return HttpResponse(
                '<?xml version="1.0"?>\n<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">\n'
                '<cas:authenticationFailure code="INVALID_TICKET">ticket has expired or been used</cas:authenticationFailure>\n'
                '</cas:serviceResponse>',
                content_type='application/xml'
            )
        
        # Mark ticket as used
        ticket_obj.is_used = True
        ticket_obj.save()
        
        # Log validation
        AuthenticationLog.objects.create(
            user=ticket_obj.user,
            service=ticket_obj.service,
            action='service_validate',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        xml_response = f'''<?xml version="1.0"?>
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
    <cas:authenticationSuccess>
        <cas:user>{ticket_obj.user.username}</cas:user>
        <cas:attributes>
            <cas:email>{ticket_obj.user.email or ''}</cas:email>
            <cas:firstName>{ticket_obj.user.first_name or ''}</cas:firstName>
            <cas:lastName>{ticket_obj.user.last_name or ''}</cas:lastName>
        </cas:attributes>
    </cas:authenticationSuccess>
</cas:serviceResponse>'''
        
        return HttpResponse(xml_response, content_type='application/xml')
        
    except Ticket.DoesNotExist:
        return HttpResponse(
            '<?xml version="1.0"?>\n<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">\n'
            '<cas:authenticationFailure code="INVALID_TICKET">ticket not found</cas:authenticationFailure>\n'
            '</cas:serviceResponse>',
            content_type='application/xml'
        )
