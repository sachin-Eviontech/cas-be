#!/usr/bin/env python3
"""
Setup script for CAS Service Management
This script helps you set up services and user access in your CAS system.
"""

import os
import sys
import django
from django.conf import settings

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cas_server.settings')
django.setup()

from django.contrib.auth.models import User
from cas_app.models import Service, ServiceGroup, UserServiceAccess, UserGroupAccess, UserProfile


def create_sample_services():
    """Create sample services for testing"""
    print("Creating sample services...")
    
    services = [
        {
            'name': 'Example Website',
            'url': 'http://localhost:5000/callback',
            'description': 'Example website for testing CAS integration'
        },
        {
            'name': 'Admin Portal',
            'url': 'http://localhost:3000/callback',
            'description': 'Administrative portal for system management'
        },
        {
            'name': 'Employee Portal',
            'url': 'http://localhost:4000/callback',
            'description': 'Employee self-service portal'
        },
        {
            'name': 'HR System',
            'url': 'http://localhost:6000/callback',
            'description': 'Human Resources management system'
        }
    ]
    
    created_services = []
    for service_data in services:
        service, created = Service.objects.get_or_create(
            name=service_data['name'],
            defaults=service_data
        )
        if created:
            print(f"✓ Created service: {service.name}")
            created_services.append(service)
        else:
            print(f"- Service already exists: {service.name}")
    
    return created_services


def create_sample_service_groups():
    """Create sample service groups"""
    print("\nCreating sample service groups...")
    
    # Get services
    services = Service.objects.all()
    
    groups = [
        {
            'name': 'Employee Services',
            'description': 'Services available to all employees',
            'services': ['Employee Portal', 'HR System']
        },
        {
            'name': 'Admin Services',
            'description': 'Services available only to administrators',
            'services': ['Admin Portal', 'HR System']
        },
        {
            'name': 'Public Services',
            'description': 'Services available to all users',
            'services': ['Example Website']
        }
    ]
    
    created_groups = []
    for group_data in groups:
        group, created = ServiceGroup.objects.get_or_create(
            name=group_data['name'],
            defaults={
                'description': group_data['description'],
                'is_active': True
            }
        )
        
        if created:
            # Add services to group
            for service_name in group_data['services']:
                try:
                    service = Service.objects.get(name=service_name)
                    group.services.add(service)
                except Service.DoesNotExist:
                    print(f"Warning: Service '{service_name}' not found")
            
            print(f"✓ Created service group: {group.name}")
            created_groups.append(group)
        else:
            print(f"- Service group already exists: {group.name}")
    
    return created_groups


def create_sample_users():
    """Create sample users for testing"""
    print("\nCreating sample users...")
    
    users_data = [
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'first_name': 'System',
            'last_name': 'Administrator',
            'is_staff': True,
            'is_superuser': True,
            'profile': {
                'department': 'IT',
                'employee_id': 'ADM001',
                'is_cas_admin': True
            }
        },
        {
            'username': 'john.doe',
            'email': 'john.doe@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'profile': {
                'department': 'Engineering',
                'employee_id': 'ENG001'
            }
        },
        {
            'username': 'jane.smith',
            'email': 'jane.smith@example.com',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'profile': {
                'department': 'HR',
                'employee_id': 'HR001'
            }
        },
        {
            'username': 'bob.wilson',
            'email': 'bob.wilson@example.com',
            'first_name': 'Bob',
            'last_name': 'Wilson',
            'profile': {
                'department': 'Marketing',
                'employee_id': 'MKT001'
            }
        }
    ]
    
    created_users = []
    for user_data in users_data:
        profile_data = user_data.pop('profile', {})
        
        user, created = User.objects.get_or_create(
            username=user_data['username'],
            defaults=user_data
        )
        
        if created:
            user.set_password('password123')  # Default password
            user.save()
            
            # Create user profile
            UserProfile.objects.create(
                user=user,
                **profile_data
            )
            
            print(f"✓ Created user: {user.username} (password: password123)")
            created_users.append(user)
        else:
            print(f"- User already exists: {user.username}")
    
    return created_users


def setup_user_access():
    """Setup user access to services"""
    print("\nSetting up user access...")
    
    # Get users and services
    admin_user = User.objects.get(username='admin')
    john_user = User.objects.get(username='john.doe')
    jane_user = User.objects.get(username='jane.smith')
    bob_user = User.objects.get(username='bob.wilson')
    
    employee_portal = Service.objects.get(name='Employee Portal')
    hr_system = Service.objects.get(name='HR System')
    admin_portal = Service.objects.get(name='Admin Portal')
    example_website = Service.objects.get(name='Example Website')
    
    # Admin has access to everything
    for service in Service.objects.filter(is_active=True):
        UserServiceAccess.objects.get_or_create(
            user=admin_user,
            service=service,
            defaults={
                'access_type': 'ALLOW',
                'granted_by': admin_user,
                'reason': 'System administrator'
            }
        )
    
    # John (Engineering) - Employee Portal and Example Website
    UserServiceAccess.objects.get_or_create(
        user=john_user,
        service=employee_portal,
        defaults={
            'access_type': 'ALLOW',
            'granted_by': admin_user,
            'reason': 'Engineering employee'
        }
    )
    UserServiceAccess.objects.get_or_create(
        user=john_user,
        service=example_website,
        defaults={
            'access_type': 'ALLOW',
            'granted_by': admin_user,
            'reason': 'Public service access'
        }
    )
    
    # Jane (HR) - Employee Portal, HR System, and Example Website
    UserServiceAccess.objects.get_or_create(
        user=jane_user,
        service=employee_portal,
        defaults={
            'access_type': 'ALLOW',
            'granted_by': admin_user,
            'reason': 'HR employee'
        }
    )
    UserServiceAccess.objects.get_or_create(
        user=jane_user,
        service=hr_system,
        defaults={
            'access_type': 'ALLOW',
            'granted_by': admin_user,
            'reason': 'HR system access'
        }
    )
    UserServiceAccess.objects.get_or_create(
        user=jane_user,
        service=example_website,
        defaults={
            'access_type': 'ALLOW',
            'granted_by': admin_user,
            'reason': 'Public service access'
        }
    )
    
    # Bob (Marketing) - Only Example Website (pending approval for others)
    UserServiceAccess.objects.get_or_create(
        user=bob_user,
        service=example_website,
        defaults={
            'access_type': 'ALLOW',
            'granted_by': admin_user,
            'reason': 'Public service access'
        }
    )
    
    # Bob requests access to Employee Portal
    UserServiceAccess.objects.get_or_create(
        user=bob_user,
        service=employee_portal,
        defaults={
            'access_type': 'PENDING',
            'reason': 'Need access for marketing reports'
        }
    )
    
    print("✓ User access permissions configured")


def print_summary():
    """Print setup summary"""
    print("\n" + "="*60)
    print("CAS SERVICE SETUP COMPLETE")
    print("="*60)
    
    print(f"\nServices created: {Service.objects.count()}")
    for service in Service.objects.all():
        print(f"  - {service.name}: {service.url}")
    
    print(f"\nService groups created: {ServiceGroup.objects.count()}")
    for group in ServiceGroup.objects.all():
        print(f"  - {group.name}: {group.services.count()} services")
    
    print(f"\nUsers created: {User.objects.count()}")
    for user in User.objects.all():
        print(f"  - {user.username} ({user.email})")
    
    print(f"\nAccess permissions: {UserServiceAccess.objects.count()}")
    
    print("\nNext steps:")
    print("1. Run migrations: python manage.py migrate")
    print("2. Start CAS server: python manage.py runserver")
    print("3. Access admin panel: http://localhost:8000/admin/")
    print("4. Test with example website: python example_website_integration.py")
    
    print("\nDefault login credentials:")
    print("  Username: admin")
    print("  Password: password123")


def main():
    """Main setup function"""
    print("Setting up CAS Service Management System...")
    print("="*50)
    
    try:
        # Create sample data
        create_sample_services()
        create_sample_service_groups()
        create_sample_users()
        setup_user_access()
        
        # Print summary
        print_summary()
        
    except Exception as e:
        print(f"Error during setup: {str(e)}")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
