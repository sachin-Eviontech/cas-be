# CAS Service Management System

A comprehensive Central Authentication Service (CAS) system that provides access control for users to specific websites and services.

## Features

- **Service Registration**: Websites can register with the CAS server
- **User Access Control**: Granular control over which users can access which services
- **Service Groups**: Group services for easier access management
- **Admin Interface**: Web-based administration panel
- **REST API**: Complete API for integration
- **Ticket-based Authentication**: Secure ticket system for service access
- **Access Request System**: Users can request access to services
- **Audit Logging**: Complete authentication and access logs

## Quick Start

### 1. Setup Environment

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Setup sample data
python setup_cas_service.py
```

### 2. Start CAS Server

```bash
python manage.py runserver
```

The CAS server will be available at `http://localhost:8000`

### 3. Access Admin Panel

Visit `http://localhost:8000/admin/` to manage:
- Services (websites that can use CAS)
- Users and their access permissions
- Service groups
- Authentication logs

## How It Works

### For Website Owners

1. **Register Your Website**: Add your website as a service in the CAS admin panel
2. **Configure Integration**: Implement CAS authentication in your website
3. **Set Access Rules**: Define which users can access your website

### For Users

1. **Login**: Users log in through the CAS server
2. **Access Control**: CAS checks if the user has permission to access the requested website
3. **Ticket Issuance**: If authorized, CAS issues a secure ticket
4. **Website Access**: The website validates the ticket and grants access

### For Administrators

1. **Manage Services**: Register and configure websites
2. **Control Access**: Grant or deny user access to specific services
3. **Monitor Usage**: View authentication logs and access patterns

## Website Integration

### Example Integration

See `example_website_integration.py` for a complete Flask example.

### Basic Integration Steps

1. **Redirect to CAS**: When a user needs to log in, redirect them to:
   ```
   http://your-cas-server.com/cas/login?service=http://your-website.com/callback
   ```

2. **Handle Callback**: After authentication, CAS redirects back with a ticket:
   ```
   http://your-website.com/callback?ticket=ST-1234567890
   ```

3. **Validate Ticket**: Validate the ticket with CAS:
   ```
   GET http://your-cas-server.com/cas/serviceValidate?ticket=ST-1234567890&service=http://your-website.com/callback
   ```

4. **Grant Access**: If validation succeeds, grant access to your website

### CAS Protocol Endpoints

- **Login**: `/cas/login?service=<your-service-url>`
- **Logout**: `/cas/logout?service=<your-service-url>`
- **Service Validation**: `/cas/serviceValidate?ticket=<ticket>&service=<service-url>`
- **Proxy Validation**: `/cas/proxyValidate?ticket=<ticket>&service=<service-url>`

## API Endpoints

### Authentication
- `POST /api/auth/login/` - Login with username/password
- `POST /api/auth/logout/` - Logout current user
- `POST /api/auth/validate/` - Validate ticket
- `GET /api/auth/user/` - Get current user info

### Service Management (Admin)
- `GET /api/services/` - List all services
- `POST /api/services/` - Create new service
- `GET /api/services/<id>/` - Get service details
- `PUT /api/services/<id>/` - Update service
- `DELETE /api/services/<id>/` - Delete service

### Access Management
- `GET /api/access/accessible-services/` - Get user's accessible services
- `POST /api/access/request/` - Request access to service
- `POST /api/access/approve/` - Approve/deny access (admin)
- `GET /api/access/pending/` - Get pending requests (admin)
- `GET /api/access/check/<service-url>/` - Check access to service

### Service Groups (Admin)
- `GET /api/service-groups/` - List service groups
- `POST /api/service-groups/` - Create service group
- `GET /api/service-groups/<id>/` - Get group details
- `PUT /api/service-groups/<id>/` - Update group
- `DELETE /api/service-groups/<id>/` - Delete group

## Access Control Models

### UserServiceAccess
Controls individual user access to specific services:
- `ALLOW`: User can access the service
- `DENY`: User is explicitly denied access
- `PENDING`: Access request pending approval

### UserGroupAccess
Controls user access to service groups:
- Same access types as UserServiceAccess
- Applies to all services in the group

### Access Hierarchy
1. **Direct Service Access**: Most specific, overrides group access
2. **Group Access**: Applies to all services in the group
3. **CAS Admin**: Admins have access to all services
4. **Default**: No access

## Configuration

### Environment Variables

Create a `.env` file with:

```env
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
DB_NAME=cas
DB_USER=postgres
DB_PASSWORD=password
DB_HOST=localhost
DB_PORT=5432
CAS_SERVER_URL=http://localhost:8000
```

### Service Registration

To register a new website:

1. Go to Admin Panel → Services
2. Click "Add Service"
3. Fill in:
   - **Name**: Display name for your website
   - **URL**: The callback URL (e.g., `http://your-site.com/callback`)
   - **Description**: Optional description
   - **Active**: Check to enable the service

### User Access Management

#### Grant Access to Individual Service
1. Go to Admin Panel → User service accesses
2. Click "Add User service access"
3. Select user and service
4. Set access type to "Allow"
5. Optionally set expiration date

#### Grant Access via Service Group
1. Create a service group in Admin Panel → Service groups
2. Add services to the group
3. Go to Admin Panel → User group accesses
4. Grant user access to the group

#### User Self-Service
Users can request access through:
- Dashboard: View accessible services and pending requests
- API: `POST /api/access/request/`

## Security Features

- **Ticket Expiration**: Service tickets expire after 5 minutes
- **Single Use**: Tickets can only be used once
- **HTTPS Support**: Secure communication
- **IP Logging**: Track authentication attempts
- **Access Auditing**: Complete audit trail

## Testing

### Test with Example Website

1. Start CAS server: `python manage.py runserver`
2. Start example website: `python example_website_integration.py`
3. Visit `http://localhost:5000`
4. Login with credentials from setup script

### Test Users

Default test users (password: `password123`):
- `admin` - Full access to all services
- `john.doe` - Engineering employee
- `jane.smith` - HR employee  
- `bob.wilson` - Marketing employee

## Troubleshooting

### Common Issues

1. **Service Not Found**: Ensure the service is registered and active
2. **Access Denied**: Check user permissions for the service
3. **Ticket Invalid**: Verify ticket hasn't expired or been used
4. **CORS Issues**: Configure CORS settings for cross-origin requests

### Logs

Check authentication logs in:
- Admin Panel → Authentication logs
- File: `logs/django.log`

### Debug Mode

Set `DEBUG=True` in settings for detailed error messages.

## Production Deployment

### Security Checklist

- [ ] Change default SECRET_KEY
- [ ] Set DEBUG=False
- [ ] Use HTTPS
- [ ] Configure proper ALLOWED_HOSTS
- [ ] Set up proper database
- [ ] Configure logging
- [ ] Set up monitoring

### Performance

- Use a production WSGI server (Gunicorn, uWSGI)
- Configure database connection pooling
- Set up Redis for session storage
- Use CDN for static files

## Support

For issues and questions:
1. Check the logs for error messages
2. Verify service registration and user permissions
3. Test with the example website integration
4. Review the API documentation

## License

This CAS system is provided as-is for educational and development purposes.
