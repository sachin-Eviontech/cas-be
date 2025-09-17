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

## Quick Start

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- pip (Python package manager)

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

#### Login Flow

1. User visits: `http://localhost:8000/cas/login/?service=https://myapp.example.com`
2. User enters credentials
3. Upon successful login, user is redirected to: `https://myapp.example.com?ticket=ST-1234567890`

#### Service Validation

Your application should validate the ticket:

```bash
curl "http://localhost:8000/cas/serviceValidate/?ticket=ST-1234567890&service=https://myapp.example.com"
```

## REST API

### Authentication Endpoints

- `POST /api/auth/login/` - Login via API
- `POST /api/auth/logout/` - Logout via API
- `POST /api/auth/validate/` - Validate ticket via API
- `GET /api/auth/user/` - Get current user info

### Service Management

- `GET /api/services/` - List all services
- `POST /api/services/` - Create new service
- `GET /api/services/{id}/` - Get service details
- `PUT /api/services/{id}/` - Update service
- `DELETE /api/services/{id}/` - Delete service

### User Data

- `GET /api/tickets/` - List user's tickets
- `GET /api/logs/` - List user's authentication logs
- `GET /api/profile/` - Get/update user profile

### Admin Endpoints

- `GET /api/admin/stats/` - Get server statistics

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

## Frontend

The application includes a modern, responsive frontend built with Tailwind CSS:

- **Login Page**: Clean, professional login interface
- **Dashboard**: User dashboard with recent activity and tickets
- **Error Pages**: User-friendly error handling
- **Responsive Design**: Works on desktop and mobile devices

## Security Features

- **CSRF Protection**: Built-in CSRF protection for forms
- **Session Security**: Secure session management
- **Ticket Expiration**: Automatic ticket expiration
- **Service Validation**: Only registered services can use CAS
- **Audit Logging**: Complete authentication audit trail
- **Input Validation**: Comprehensive input validation

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
