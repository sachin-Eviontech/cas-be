# Django CAS Server

A comprehensive Central Authentication Service (CAS) server built with Django, featuring REST APIs, PostgreSQL database, and a modern Tailwind CSS frontend.

## Features

- **CAS Protocol Support**: Full implementation of CAS 3.0 protocol
- **REST API**: Complete REST API for integration with other services
- **PostgreSQL Database**: Robust database backend with proper indexing
- **Modern UI**: Beautiful, responsive interface built with Tailwind CSS
- **Service Management**: Register and manage trusted services
- **Ticket System**: Secure ticket-based authentication
- **Proxy Support**: Support for proxy authentication
- **Admin Interface**: Django admin for easy management
- **Audit Logging**: Comprehensive authentication logging
- **User Profiles**: Extended user profiles with additional fields
- **Access Management**: Granular control over user access to services
- **Service Groups**: Organize services into groups for easier management
- **Access Requests**: Users can request access to specific services
- **Approval Workflow**: Admin approval system for service access

## Quick Start

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- pip (Python package manager)

### Dependencies

The project uses the following key dependencies:

- **Django 4.2.7** - Web framework
- **djangorestframework 3.14.0** - REST API framework
- **psycopg2-binary 2.9.9** - PostgreSQL adapter
- **django-cors-headers 4.3.1** - CORS handling
- **python-decouple 3.8** - Environment variable management
- **Pillow 10.1.0** - Image processing
- **django-extensions 3.2.3** - Django extensions
- **whitenoise 6.6.0** - Static file serving
- **gunicorn 21.2.0** - WSGI server

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cas-be
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

5. **Set up PostgreSQL database**
   ```sql
   CREATE DATABASE cas_database;
   CREATE USER cas_user WITH PASSWORD 'your_password';
   GRANT ALL PRIVILEGES ON DATABASE cas_database TO cas_user;
   ```

6. **Run migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

7. **Create superuser**
   ```bash
   python manage.py createsuperuser
   ```

8. **Run the server**
   ```bash
   python manage.py runserver
   ```

### Quick Setup with Management Command

The project includes a management command to quickly set up the CAS server with sample data:

```bash
python manage.py setup_cas
```

This command will:
- Create sample services
- Create service groups
- Set up sample users
- Create access permissions
- Generate sample tickets for testing

This is useful for development and testing purposes.

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Settings
DB_NAME=cas_database
DB_USER=postgres
DB_PASSWORD=your-password-here
DB_HOST=localhost
DB_PORT=5432

# CAS Server Settings
CAS_SERVER_URL=http://localhost:8000
```

### Database Configuration

The application uses PostgreSQL as the default database. Make sure PostgreSQL is running and accessible with the credentials provided in your `.env` file.

## CAS Protocol Endpoints

### Authentication

- **Login**: `GET/POST /cas/login/`
- **Logout**: `GET /cas/logout/`
- **Service Validation**: `GET /cas/serviceValidate/`
- **Ticket Validation**: `GET /cas/validate/`
- **Proxy Validation**: `GET /cas/proxyValidate/`

### Usage Examples

#### Service Registration

Register a service in the Django admin or via API:

```python
Service.objects.create(
    name="My Application",
    url="https://myapp.example.com",
    description="My trusted application",
    is_active=True
)
```

#### Traditional CAS Login Flow (Ticket-based)

1. User visits: `http://localhost:8000/cas/login/?service=https://myapp.example.com`
2. User enters credentials
3. Upon succes--0sful login, user is redirected to: `https://myapp.example.com?ticket=ST-1234567890`

#### Token-based Login Flow (Recommended)

1. User visits: `http://localhost:8000/cas/token/?service=https://myapp.example.com`
2. User enters credentials
3. Upon successful login, user is redirected to: `https://myapp.example.com?token=JWT_TOKEN_HERE`

#### Service Validation

**Traditional CAS (Ticket-based):**
```bash
curl "http://localhost:8000/cas/serviceValidate/?ticket=ST-1234567890&service=https://myapp.example.com"
```

**Token-based (Recommended):**
```bash
curl -X POST "http://localhost:8000/api/token/validate/" \
  -H "Content-Type: application/json" \
  -d '{"token": "JWT_TOKEN_HERE", "service": "https://myapp.example.com"}'
```

## REST API

### Root Endpoint

- `GET /api/` - API root with endpoint documentation

### Authentication Endpoints

- `POST /api/auth/login/` - Login via API
- `POST /api/auth/logout/` - Logout via API
- `POST /api/auth/validate/` - Validate ticket via API
- `GET /api/auth/user/` - Get current user info

### Service-Specific Token Authentication Endpoints (Recommended)

- `POST /api/token/login/` - Login and get service-specific JWT tokens (service parameter REQUIRED)
- `POST /api/token/refresh/` - Refresh service-specific access token  
- `POST /api/token/logout/` - Logout
- `POST /api/token/validate/` - Validate service-specific JWT token (service parameter REQUIRED)
- `POST /api/token/user/` - Get user info from service-specific token (service parameter REQUIRED)
- `POST /api/user/services/` - Get accessible services for user (requires username/password)

### Service Management

- `GET /api/services/` - List all services
- `POST /api/services/` - Create new service
- `GET /api/services/{id}/` - Get service details
- `PUT /api/services/{id}/` - Update service
- `DELETE /api/services/{id}/` - Delete service

### Service Groups Management

- `GET /api/service-groups/` - List all service groups
- `POST /api/service-groups/` - Create new service group
- `GET /api/service-groups/{id}/` - Get service group details
- `PUT /api/service-groups/{id}/` - Update service group
- `DELETE /api/service-groups/{id}/` - Delete service group

### User Data

- `GET /api/tickets/` - List user's tickets
- `GET /api/logs/` - List user's authentication logs
- `GET /api/profile/` - Get/update user profile

### Access Management

- `GET /api/access/service/` - List user service access permissions
- `GET /api/access/group/` - List user group access permissions
- `GET /api/access/accessible-services/` - Get services user can access
- `POST /api/access/request/` - Request access to a service
- `POST /api/access/approve/` - Approve/deny access requests
- `GET /api/access/pending/` - List pending access requests
- `GET /api/access/check/{service_url}/` - Check access to specific service

### Admin Endpoints

- `GET /api/admin/stats/` - Get server statistics

### Documentation Endpoints

- `GET /api/docs/` - Interactive API documentation
- `GET /api/schema/` - API schema
- `GET /api/documentation/` - API documentation

## API Usage Examples

### Login

```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "myuser",
    "password": "mypassword",
    "service": "https://myapp.example.com"
  }'
```

### Validate Ticket

```bash
curl -X POST http://localhost:8000/api/auth/validate/ \
  -H "Content-Type: application/json" \
  -d '{
    "ticket": "ST-1234567890",
    "service": "https://myapp.example.com"
  }'
```

## Access Management

The CAS server includes comprehensive access management features that allow fine-grained control over which users can access which services.

### Service Groups

Services can be organized into groups for easier management:

```python
# Create a service group
ServiceGroup.objects.create(
    name="HR Services",
    description="Human Resources related services",
    is_active=True
)

# Add services to the group
hr_group = ServiceGroup.objects.get(name="HR Services")
hr_group.services.add(service1, service2, service3)
```

### User Access Control

Users can be granted or denied access to specific services or service groups:

```python
# Grant access to a specific service
UserServiceAccess.objects.create(
    user=user,
    service=service,
    access_type='ALLOW',
    granted_by=admin_user,
    granted_at=timezone.now(),
    reason="User needs access for their role"
)

# Grant access to a service group
UserGroupAccess.objects.create(
    user=user,
    service_group=hr_group,
    access_type='ALLOW',
    granted_by=admin_user,
    granted_at=timezone.now()
)
```

### Access Request Workflow

Users can request access to services through the API:

```bash
# Request access to a service
curl -X POST http://localhost:8000/api/access/request/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token your-token-here" \
  -d '{
    "service_url": "https://hr.example.com",
    "reason": "Need access for employee management tasks"
  }'
```

### Access Approval

Admins can approve or deny access requests:

```bash
# Approve an access request
curl -X POST http://localhost:8000/api/access/approve/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token admin-token-here" \
  -d '{
    "access_id": 123,
    "action": "approve",
    "reason": "Access approved for role requirements"
  }'
```

### Check User Access

Check if a user has access to a specific service:

```bash
# Check access to a service
curl -X GET http://localhost:8000/api/access/check/https://hr.example.com/ \
  -H "Authorization: Token user-token-here"
```

## Service-Specific Token Authentication (Recommended)

The service-specific token authentication system provides a modern, secure approach where each service gets its own unique tokens. This ensures maximum security and proper access control.

### Key Benefits

- **Service-specific security** - Each service gets unique tokens that only work for that service
- **No cross-service token reuse** - Tokens cannot be used across different services
- **Stateless** - No server-side session storage needed
- **JWT tokens** - Industry standard, self-contained tokens with service information
- **Fine-grained access control** - Per-service permissions enforced at token level
- **Easy integration** - Simple HTTP API calls with built-in service validation

### How It Works

1. **Service Registration**: Each service must be registered in CAS with a unique URL
2. **User Access Grant**: Admins grant users access to specific services
3. **User Login**: User visits service and is redirected to CAS with service parameter
4. **Authentication**: User authenticates and CAS checks service access permissions
5. **Token Generation**: CAS generates service-specific JWT tokens (access + refresh)
6. **Service Redirect**: User is redirected back to service with service-specific token
7. **Token Validation**: Service validates token with CAS, confirming service match
8. **Access Granted**: Service grants access if token is valid and matches service

### Service-Specific Login Flow

#### Web Application Integration

**IMPORTANT**: Service parameter is REQUIRED for all token operations.

```html
<!-- Redirect user to CAS token login with YOUR service URL -->
<a href="http://localhost:8000/cas/token/?service=https://myapp.example.com">
    Login with CAS
</a>
```

After successful login and access verification, user is redirected to:
```
https://myapp.example.com?token=JWT_SERVICE_SPECIFIC_TOKEN
```

**The token is ONLY valid for `https://myapp.example.com` and cannot be used by other services.**

#### API Integration

**IMPORTANT**: Service parameter is REQUIRED for all API calls.

```bash
# Login and get service-specific tokens
curl -X POST http://localhost:8000/api/token/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "password123",
    "service": "https://myapp.example.com"
  }'

# Response
{
  "success": true,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "username": "user@example.com",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  },
  "service": {
    "id": 1,
    "name": "My Application",
    "url": "https://myapp.example.com",
    "description": "My web application"
  },
  "message": "Login successful and tokens generated for service"
}
```

### Service Integration

#### Validate Token and Check Access

```bash
# Validate token and check service access
curl -X POST http://localhost:8000/api/token/validate/ \
  -H "Content-Type: application/json" \
  -d '{
    "token": "JWT_ACCESS_TOKEN_HERE",
    "service": "https://myapp.example.com"
  }'

# Response
{
  "success": true,
  "user": "user@example.com",
  "attributes": {
    "username": "user@example.com",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "is_active": true
  },
  "service_access": {
    "service_url": "https://myapp.example.com",
    "has_access": true,
    "message": "Access granted"
  }
}
```

#### Check Service Access Only

```bash
# Check if user has access to specific service
curl -X POST http://localhost:8000/api/token/check-access/ \
  -H "Content-Type: application/json" \
  -d '{
    "token": "JWT_ACCESS_TOKEN_HERE",
    "service_url": "https://myapp.example.com"
  }'

# Response
{
  "success": true,
  "has_access": true,
  "message": "Access granted",
  "service_url": "https://myapp.example.com"
}
```

#### Get User's Accessible Services

```bash
# Get all services user has access to
curl -X GET "http://localhost:8000/api/token/services/?token=JWT_ACCESS_TOKEN_HERE"

# Response
{
  "success": true,
  "accessible_services": [
    {
      "id": 1,
      "name": "HR System",
      "url": "https://hr.example.com",
      "description": "Human Resources Management",
      "access_type": "ALLOW",
      "access_method": "direct",
      "granted_at": "2024-01-15T10:30:00Z",
      "expires_at": null
    },
    {
      "id": 2,
      "name": "Finance Portal",
      "url": "https://finance.example.com",
      "description": "Financial Management",
      "access_type": "ALLOW",
      "access_method": "group",
      "group_name": "Finance Team",
      "granted_at": "2024-01-10T09:00:00Z",
      "expires_at": "2024-12-31T23:59:59Z"
    }
  ],
  "count": 2
}
```

### Token Refresh

```bash
# Refresh access token using refresh token
curl -X POST http://localhost:8000/api/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "JWT_REFRESH_TOKEN_HERE"
  }'

# Response
{
  "success": true,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Service Implementation Example

Here's how to integrate token validation in your service:

```python
import requests
import json

class CASServiceIntegration:
    def __init__(self, cas_server_url, service_url):
        self.cas_server_url = cas_server_url.rstrip('/')
        self.service_url = service_url
    
    def validate_token(self, token):
        """Validate token and check service access"""
        try:
            response = requests.post(
                f"{self.cas_server_url}/api/token/validate/",
                json={
                    "token": token,
                    "service": self.service_url
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('success', False), data
            return False, None
                
        except requests.RequestException as e:
            print(f"Error validating token: {e}")
            return False, None
    
    def check_access(self, token):
        """Check if user has access to this service"""
        try:
            response = requests.post(
                f"{self.cas_server_url}/api/token/check-access/",
                json={
                    "token": token,
                    "service_url": self.service_url
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('has_access', False), data.get('message', 'Unknown error')
            return False, f"HTTP {response.status_code}"
                
        except requests.RequestException as e:
            return False, f"Request error: {e}"

# Usage in your service
def handle_request(request):
    token = request.GET.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return {'error': 'No token provided', 'status': 401}
    
    cas = CASServiceIntegration('http://localhost:8000', 'https://myapp.example.com')
    
    # Validate token
    is_valid, validation_data = cas.validate_token(token)
    if not is_valid:
        return {'error': 'Invalid or expired token', 'status': 401}
    
    # Check service access
    has_access, message = cas.check_access(token)
    if not has_access:
        return {'error': f'Access denied: {message}', 'status': 403}
    
    # Grant access
    return {
        'message': 'Welcome to the service!',
        'user': validation_data.get('user'),
        'status': 200
    }
```

### Configuration

Add these settings to your Django settings for token-based authentication:

```python
# JWT Settings
JWT_SECRET_KEY = 'your-secret-key-change-this-in-production'
JWT_ACCESS_TOKEN_LIFETIME = 60 * 60  # 1 hour
JWT_REFRESH_TOKEN_LIFETIME = 7 * 24 * 60 * 60  # 7 days
```

### Security Considerations

1. **Use HTTPS** in production for all token transmission
2. **Rotate JWT secret keys** regularly
3. **Set appropriate token lifetimes** based on your security requirements
4. **Validate tokens on every request** to services
5. **Implement proper error handling** for token validation failures

## Integration with Django Projects

This section explains how to integrate the CAS server with your other Django projects for authentication.

### Prerequisites

1. **Register Your Service**: First, register your Django project as a service in the CAS server admin panel or via API
2. **Install Dependencies**: Add required packages to your Django project

### Method 1: Using Django CAS Client Library

#### Installation

```bash
pip install django-cas-ng
```

#### Configuration

Add to your Django project's `settings.py`:

```python
# CAS Configuration
CAS_SERVER_URL = 'http://localhost:8000'
CAS_VERSION = '3'
CAS_APPLY_ATTRIBUTES_TO_USER = True
CAS_RENAME_ATTRIBUTES = {
    'email': 'email',
    'firstName': 'first_name',
    'lastName': 'last_name',
    'department': 'department',
    'employee_id': 'employee_id',
}

# Add CAS authentication backend
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'django_cas_ng.backends.CASBackend',
)

# Add CAS middleware
MIDDLEWARE = [
    # ... other middleware
    'django_cas_ng.middleware.CASMiddleware',
]

# Add CAS URLs
INSTALLED_APPS = [
    # ... other apps
    'django_cas_ng',
]
```

#### URL Configuration

Add to your `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    # ... other URLs
    path('accounts/', include('django_cas_ng.urls')),
]
```

#### Usage in Views

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def protected_view(request):
    # User is automatically authenticated via CAS
    return render(request, 'protected.html', {
        'user': request.user
    })
```

### Method 2: Custom Integration with REST API

#### Installation

```bash
pip install requests
```

#### Create CAS Client

Create `cas_client.py` in your Django project:

```python
import requests
import xml.etree.ElementTree as ET
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

User = get_user_model()

class CASBackend(BaseBackend):
    def authenticate(self, request, ticket=None, service=None):
        if not ticket or not service:
            return None
            
        # Validate ticket with CAS server
        cas_validate_url = f"{settings.CAS_SERVER_URL}/cas/serviceValidate"
        params = {
            'ticket': ticket,
            'service': service
        }
        
        try:
            response = requests.get(cas_validate_url, params=params, timeout=10)
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                
                # Check for authentication success
                success_elem = root.find('.//{http://www.yale.edu/tp/cas}authenticationSuccess')
                if success_elem is not None:
                    user_elem = success_elem.find('{http://www.yale.edu/tp/cas}user')
                    if user_elem is not None:
                        username = user_elem.text
                        
                        # Get or create user
                        user, created = User.objects.get_or_create(username=username)
                        
                        # Update user attributes
                        attrs_elem = success_elem.find('{http://www.yale.edu/tp/cas}attributes')
                        if attrs_elem is not None:
                            for attr in attrs_elem:
                                tag = attr.tag.replace('{http://www.yale.edu/tp/cas}', '')
                                if tag == 'email':
                                    user.email = attr.text
                                elif tag == 'firstName':
                                    user.first_name = attr.text
                                elif tag == 'lastName':
                                    user.last_name = attr.text
                            user.save()
                        
                        return user
        except Exception as e:
            print(f"CAS authentication error: {e}")
            
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
```

#### Configuration

Add to your `settings.py`:

```python
# CAS Configuration
CAS_SERVER_URL = 'http://localhost:8000'

# Add custom CAS backend
AUTHENTICATION_BACKENDS = [
    'myapp.cas_client.CASBackend',
    'django.contrib.auth.backends.ModelBackend',
]
```

#### Create Authentication Views

Create `cas_views.py`:

```python
from django.shortcuts import redirect
from django.contrib.auth import login
from django.conf import settings
from django.http import HttpResponse
from urllib.parse import urlencode

def cas_login(request):
    """Redirect to CAS login"""
    service_url = request.build_absolute_uri('/cas/callback/')
    cas_login_url = f"{settings.CAS_SERVER_URL}/cas/login/?service={service_url}"
    return redirect(cas_login_url)

def cas_callback(request):
    """Handle CAS callback"""
    ticket = request.GET.get('ticket')
    if not ticket:
        return HttpResponse("No ticket provided", status=400)
    
    service_url = request.build_absolute_uri('/cas/callback/')
    
    # Authenticate user
    from django.contrib.auth import authenticate
    user = authenticate(request=request, ticket=ticket, service=service_url)
    
    if user:
        login(request, user)
        return redirect('/')  # Redirect to your main page
    else:
        return HttpResponse("Authentication failed", status=400)

def cas_logout(request):
    """Logout and redirect to CAS logout"""
    from django.contrib.auth import logout
    logout(request)
    
    cas_logout_url = f"{settings.CAS_SERVER_URL}/cas/logout/"
    return redirect(cas_logout_url)
```

#### URL Configuration

Add to your `urls.py`:

```python
from django.urls import path
from . import cas_views

urlpatterns = [
    # ... other URLs
    path('cas/login/', cas_views.cas_login, name='cas_login'),
    path('cas/callback/', cas_views.cas_callback, name='cas_callback'),
    path('cas/logout/', cas_views.cas_logout, name='cas_logout'),
]
```

### Method 3: Using API Authentication

For applications that need to authenticate via API:

```python
import requests
from django.contrib.auth import login
from django.http import JsonResponse

def api_login(request):
    """Login via CAS API"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        service_url = request.build_absolute_uri('/')
        
        # Authenticate with CAS API
        cas_api_url = f"{settings.CAS_SERVER_URL}/api/auth/login/"
        data = {
            'username': username,
            'password': password,
            'service': service_url
        }
        
        response = requests.post(cas_api_url, json=data)
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                # Create or get user
                user, created = User.objects.get_or_create(
                    username=username,
                    defaults={'email': result.get('user', {}).get('email', '')}
                )
                login(request, user)
                return JsonResponse({'success': True})
        
        return JsonResponse({'success': False, 'error': 'Authentication failed'})
    
    return render(request, 'login.html')
```

### Service Registration

Before integrating, register your Django project as a service:

#### Via Admin Panel

1. Go to `http://localhost:8000/admin/`
2. Navigate to Services
3. Add a new service with your project's URL

#### Via API

```python
import requests

def register_service():
    service_data = {
        'name': 'My Django Project',
        'url': 'http://localhost:8001',  # Your Django project URL
        'description': 'My Django application',
        'is_active': True
    }
    
    response = requests.post(
        f"{settings.CAS_SERVER_URL}/api/services/",
        json=service_data,
        headers={'Authorization': f'Token {admin_token}'}
    )
    
    if response.status_code == 201:
        print("Service registered successfully")
    else:
        print(f"Registration failed: {response.text}")
```

### Testing Integration

1. **Start CAS Server**: `python manage.py runserver` (port 8000)
2. **Start Your Django Project**: `python manage.py runserver 8001`
3. **Register Service**: Add your project as a service in CAS admin
4. **Test Login**: Visit your project's login URL

### Example Integration

See `example_website_integration.py` for a complete Flask example showing how to integrate with the CAS server.

## Data Models

The CAS server includes several data models to manage authentication, services, and access control:

### Core Models

#### Service
Represents a registered CAS service that can authenticate users:
- `name`: Unique service name
- `url`: Service URL for validation
- `description`: Optional service description
- `is_active`: Whether the service is active
- `created_at`, `updated_at`: Timestamps

#### Ticket
Represents CAS authentication tickets:
- `ticket_id`: Unique ticket identifier (TGT-, ST-, or PT- prefix)
- `ticket_type`: Type of ticket (TGT, ST, PT)
- `user`: Associated user
- `service`: Associated service (for ST/PT tickets)
- `created_at`, `expires_at`: Creation and expiration timestamps
- `is_used`, `is_valid`: Usage and validity flags

#### ProxyGrantingTicket (PGT)
Represents proxy granting tickets for proxy authentication:
- `pgt_id`: Unique PGT identifier
- `user`: Associated user
- `created_at`, `expires_at`: Creation and expiration timestamps
- `is_used`, `is_valid`: Usage and validity flags

### Access Management Models

#### ServiceGroup
Groups services for easier access management:
- `name`: Unique group name
- `description`: Optional group description
- `services`: Many-to-many relationship with Services
- `is_active`: Whether the group is active
- `created_at`, `updated_at`: Timestamps

#### UserServiceAccess
Controls user access to specific services:
- `user`: Associated user
- `service`: Associated service
- `access_type`: ALLOW, DENY, or PENDING
- `granted_by`: Admin who granted/denied access
- `granted_at`: When access was granted/denied
- `expires_at`: Optional expiration date
- `reason`: Reason for access decision
- `is_active`: Whether the access rule is active

#### UserGroupAccess
Controls user access to service groups:
- `user`: Associated user
- `service_group`: Associated service group
- `access_type`: ALLOW, DENY, or PENDING
- `granted_by`: Admin who granted/denied access
- `granted_at`: When access was granted/denied
- `expires_at`: Optional expiration date
- `reason`: Reason for access decision
- `is_active`: Whether the access rule is active

### User and Logging Models

#### UserProfile
Extended user profile with additional fields:
- `user`: One-to-one relationship with Django User
- `phone_number`: User's phone number
- `department`: User's department
- `employee_id`: Employee identifier
- `is_cas_admin`: Whether user is a CAS administrator
- `created_at`, `updated_at`: Timestamps

#### AuthenticationLog
Logs all authentication activities:
- `user`: Associated user (can be null for failed attempts)
- `service`: Associated service (can be null)
- `action`: Type of action (login, logout, validate, etc.)
- `ip_address`: Client IP address
- `user_agent`: Client user agent
- `success`: Whether the action was successful
- `details`: Additional details as JSON
- `created_at`: Timestamp

## Frontend

The application includes a modern, responsive frontend built with Tailwind CSS:

- **Login Page**: Clean, professional login interface
- **Dashboard**: User dashboard with recent activity and tickets
- **Error Pages**: User-friendly error handling
- **Responsive Design**: Works on desktop and mobile devices

## Security Features

- **CSRF Protection**: Built-in CSRF protection for forms with custom API exemption
- **Session Security**: Secure session management with configurable timeouts
- **Ticket Expiration**: Automatic ticket expiration with configurable lifetimes
- **Service Validation**: Only registered services can use CAS
- **Audit Logging**: Complete authentication audit trail with IP and user agent tracking
- **Input Validation**: Comprehensive input validation and sanitization
- **CORS Configuration**: Configurable CORS settings for cross-origin requests
- **XSS Protection**: Browser XSS filter and content type sniffing protection
- **Frame Options**: X-Frame-Options set to DENY to prevent clickjacking
- **Token Authentication**: REST API uses secure token-based authentication
- **Access Control**: Granular user access control with approval workflows
- **Secure Headers**: Security headers for enhanced protection
- **Environment-based Configuration**: Secure configuration management with python-decouple

## Development

### Running Tests

```bash
python manage.py test
```

### Code Style

The project follows Django best practices and PEP 8 style guidelines.

### Adding New Features

1. Create models in `cas_app/models.py`
2. Add serializers in `cas_app/serializers.py`
3. Create views in `cas_app/views.py` or `cas_app/api_views.py`
4. Add URL patterns in `cas_app/urls.py` or `cas_app/api_urls.py`
5. Create templates in `templates/cas/`
6. Run migrations: `python manage.py makemigrations && python manage.py migrate`

## Deployment

### Production Settings

1. Set `DEBUG=False` in your environment
2. Configure proper `ALLOWED_HOSTS`
3. Use a production database
4. Set up static file serving
5. Configure HTTPS
6. Set up proper logging

### Docker Deployment

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN python manage.py collectstatic --noinput
CMD ["gunicorn", "cas_server.wsgi:application"]
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue in the repository.

## Changelog

### Version 2.0.0
- **Access Management System**: Added comprehensive user access control
- **Service Groups**: Added ability to group services for easier management
- **Access Request Workflow**: Users can request access to services with admin approval
- **Enhanced User Profiles**: Extended user profiles with additional fields
- **Improved Security**: Enhanced security features and middleware
- **Management Commands**: Added setup_cas command for quick development setup
- **API Documentation**: Enhanced API documentation and schema
- **CORS Support**: Added CORS configuration for cross-origin requests
- **Token Authentication**: Enhanced REST API with token-based authentication
- **Audit Logging**: Improved logging with IP and user agent tracking

### Version 1.0.0
- Initial release
- CAS 3.0 protocol support
- REST API implementation
- PostgreSQL database
- Tailwind CSS frontend
- Admin interface
- Service management
- Ticket system
- Proxy authentication
- Audit logging

## Complete Service Integration Guide

This section provides a comprehensive guide for integrating your application with the service-specific CAS system.

### Step 1: Register Your Service

First, register your service in the CAS system:

```python
# Via Django shell or management command
from cas_app.models import Service

service = Service.objects.create(
    name="My Application",
    url="https://myapp.example.com",  # EXACT URL - must match exactly
    description="My web application",
    is_active=True
)
```

Or via API (admin required):
```bash
curl -X POST http://localhost:8000/api/services/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token admin-token-here" \
  -d '{
    "name": "My Application",
    "url": "https://myapp.example.com",
    "description": "My web application",
    "is_active": true
  }'
```

### Step 2: Grant User Access

Grant users access to your service:

```python
# Via Django shell
from django.contrib.auth.models import User
from cas_app.models import Service, UserServiceAccess
from django.utils import timezone

user = User.objects.get(username='john.doe')
service = Service.objects.get(url='https://myapp.example.com')

UserServiceAccess.objects.create(
    user=user,
    service=service,
    access_type='ALLOW',
    granted_by=admin_user,
    granted_at=timezone.now(),
    reason="User needs access for their role"
)
```

### Step 3: Implement Service Integration

#### Python/Django Example

```python
import requests
from django.shortcuts import redirect
from django.http import JsonResponse

CAS_SERVER_URL = "http://localhost:8000"
SERVICE_URL = "https://myapp.example.com"  # YOUR service URL

def login_required_view(request):
    """Example view that requires CAS authentication"""
    
    # Check for token in request
    token = request.GET.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        # Redirect to CAS login
        cas_login_url = f"{CAS_SERVER_URL}/cas/token/?service={SERVICE_URL}"
        return redirect(cas_login_url)
    
    # Validate token with CAS
    validation_response = requests.post(
        f"{CAS_SERVER_URL}/api/token/validate/",
        json={
            "token": token,
            "service": SERVICE_URL
        },
        timeout=10
    )
    
    if validation_response.status_code == 200:
        data = validation_response.json()
        if data.get('success'):
            # Token is valid, user has access
            user_info = data.get('user')
            service_info = data.get('service')
            
            # Store user info in session or process request
            request.session['cas_user'] = user_info
            request.session['cas_service'] = service_info
            
            # Your application logic here
            return JsonResponse({
                'message': 'Welcome to the service!',
                'user': user_info,
                'service': service_info
            })
    
    # Token validation failed, redirect to login
    cas_login_url = f"{CAS_SERVER_URL}/cas/token/?service={SERVICE_URL}"
    return redirect(cas_login_url)


def api_endpoint(request):
    """Example API endpoint with token validation"""
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return JsonResponse({
            'error': 'Token required',
            'cas_login_url': f"{CAS_SERVER_URL}/cas/token/?service={SERVICE_URL}"
        }, status=401)
    
    # Validate token
    validation_response = requests.post(
        f"{CAS_SERVER_URL}/api/token/validate/",
        json={
            "token": token,
            "service": SERVICE_URL
        },
        timeout=10
    )
    
    if validation_response.status_code != 200:
        return JsonResponse({
            'error': 'Token validation failed',
            'cas_login_url': f"{CAS_SERVER_URL}/cas/token/?service={SERVICE_URL}"
        }, status=401)
    
    data = validation_response.json()
    if not data.get('success'):
        return JsonResponse({
            'error': data.get('message', 'Token invalid'),
            'cas_login_url': f"{CAS_SERVER_URL}/cas/token/?service={SERVICE_URL}"
        }, status=401)
    
    # Token is valid, process API request
    return JsonResponse({
        'message': 'API access granted',
        'user': data.get('user'),
        'service': data.get('service')
    })
```

#### Flask Example

```python
from flask import Flask, request, redirect, jsonify
import requests

app = Flask(__name__)
CAS_SERVER_URL = "http://localhost:8000"
SERVICE_URL = "https://myapp.example.com"

@app.route('/')
def home():
    token = request.args.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        cas_login_url = f"{CAS_SERVER_URL}/cas/token/?service={SERVICE_URL}"
        return redirect(cas_login_url)
    
    # Validate token
    response = requests.post(
        f"{CAS_SERVER_URL}/api/token/validate/",
        json={"token": token, "service": SERVICE_URL}
    )
    
    if response.status_code == 200 and response.json().get('success'):
        data = response.json()
        return jsonify({
            'message': 'Welcome!',
            'user': data.get('user'),
            'service': data.get('service')
        })
    
    cas_login_url = f"{CAS_SERVER_URL}/cas/token/?service={SERVICE_URL}"
    return redirect(cas_login_url)

@app.route('/api/data')
def api_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({'error': 'Token required'}), 401
    
    response = requests.post(
        f"{CAS_SERVER_URL}/api/token/validate/",
        json={"token": token, "service": SERVICE_URL}
    )
    
    if response.status_code == 200 and response.json().get('success'):
        return jsonify({'data': 'Your API data here'})
    
    return jsonify({'error': 'Invalid token'}), 401
```

#### JavaScript/Node.js Example

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

const CAS_SERVER_URL = 'http://localhost:8000';
const SERVICE_URL = 'https://myapp.example.com';

app.get('/', async (req, res) => {
    const token = req.query.token || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        const casLoginUrl = `${CAS_SERVER_URL}/cas/token/?service=${SERVICE_URL}`;
        return res.redirect(casLoginUrl);
    }
    
    try {
        const response = await axios.post(`${CAS_SERVER_URL}/api/token/validate/`, {
            token: token,
            service: SERVICE_URL
        });
        
        if (response.data.success) {
            res.json({
                message: 'Welcome!',
                user: response.data.user,
                service: response.data.service
            });
        } else {
            const casLoginUrl = `${CAS_SERVER_URL}/cas/token/?service=${SERVICE_URL}`;
            res.redirect(casLoginUrl);
        }
    } catch (error) {
        const casLoginUrl = `${CAS_SERVER_URL}/cas/token/?service=${SERVICE_URL}`;
        res.redirect(casLoginUrl);
    }
});

app.get('/api/data', async (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }
    
    try {
        const response = await axios.post(`${CAS_SERVER_URL}/api/token/validate/`, {
            token: token,
            service: SERVICE_URL
        });
        
        if (response.data.success) {
            res.json({ data: 'Your API data here' });
        } else {
            res.status(401).json({ error: 'Invalid token' });
        }
    } catch (error) {
        res.status(401).json({ error: 'Token validation failed' });
    }
});
```

### Step 4: Handle Token Refresh (Optional)

```python
def refresh_token_if_needed(refresh_token):
    """Refresh access token if needed"""
    
    response = requests.post(
        f"{CAS_SERVER_URL}/api/token/refresh/",
        json={"refresh_token": refresh_token}
    )
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            return data.get('access_token')
    
    return None
```

### Step 5: Testing Your Integration

1. **Register your service** in CAS admin panel or via API
2. **Grant user access** to your service
3. **Test the flow**:
   - Visit your service without token
   - Should redirect to CAS login
   - Login with valid credentials
   - Should redirect back to your service with token
   - Service should validate token and grant access

### Important Notes

1. **Service URL must match exactly** - The URL in your service registration must exactly match the URL you use in API calls
2. **Tokens are service-specific** - Tokens generated for one service cannot be used with another service
3. **Always validate tokens** - Never trust tokens without validating them with the CAS server
4. **Handle errors gracefully** - Always provide fallback to CAS login when token validation fails
5. **Use HTTPS in production** - All token transmission should be over HTTPS in production

### Troubleshooting

**Token validation fails:**
- Check that service URL matches exactly
- Verify user has access to the service
- Check token hasn't expired
- Ensure CAS server is accessible

**User gets access denied:**
- Verify user has been granted access to the service
- Check service is active
- Verify access hasn't expired

**Redirect loop:**
- Check service URL matches registration
- Verify token parameter is being passed correctly
- Check for JavaScript or framework issues preventing token extraction
