from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from cas_app.models import Service, UserProfile


class Command(BaseCommand):
    help = 'Set up initial CAS server data'

    def handle(self, *args, **options):
        self.stdout.write('Setting up CAS server...')
        
        # Create a demo service
        service, created = Service.objects.get_or_create(
            name='Demo Application',
            defaults={
                'url': 'http://localhost:3000',
                'description': 'Demo application for testing CAS',
                'is_active': True
            }
        )
        
        if created:
            self.stdout.write(
                self.style.SUCCESS(f'Created demo service: {service.name}')
            )
        else:
            self.stdout.write(f'Demo service already exists: {service.name}')
        
        # Create a demo user if it doesn't exist
        if not User.objects.filter(username='demo').exists():
            user = User.objects.create_user(
                username='demo',
                email='demo@example.com',
                password='demo123',
                first_name='Demo',
                last_name='User'
            )
            
            # Create user profile
            UserProfile.objects.create(
                user=user,
                department='IT',
                employee_id='DEMO001',
                phone_number='+1234567890'
            )
            
            self.stdout.write(
                self.style.SUCCESS('Created demo user: demo/demo123')
            )
        else:
            self.stdout.write('Demo user already exists')
        
        self.stdout.write(
            self.style.SUCCESS('CAS server setup completed!')
        )
