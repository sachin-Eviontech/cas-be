from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid


class Service(models.Model):
    """CAS Service model for registered services"""
    name = models.CharField(max_length=255, unique=True)
    url = models.URLField(max_length=500)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class Ticket(models.Model):
    """CAS Ticket model for authentication tickets"""
    TICKET_TYPES = [
        ('TGT', 'Ticket Granting Ticket'),
        ('ST', 'Service Ticket'),
        ('PT', 'Proxy Ticket'),
    ]
    
    ticket_id = models.CharField(max_length=255, unique=True, primary_key=True)
    ticket_type = models.CharField(max_length=3, choices=TICKET_TYPES)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    is_valid = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.ticket_type}:{self.ticket_id}"
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def save(self, *args, **kwargs):
        if not self.ticket_id:
            self.ticket_id = f"{self.ticket_type}-{uuid.uuid4().hex}"
        super().save(*args, **kwargs)


class ProxyGrantingTicket(models.Model):
    """Proxy Granting Ticket for proxy authentication"""
    pgt_id = models.CharField(max_length=255, unique=True, primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    is_valid = models.BooleanField(default=True)
    
    def __str__(self):
        return f"PGT:{self.pgt_id}"
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def save(self, *args, **kwargs):
        if not self.pgt_id:
            self.pgt_id = f"PGT-{uuid.uuid4().hex}"
        super().save(*args, **kwargs)


class AuthenticationLog(models.Model):
    """Log authentication attempts and activities"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=50)  # login, logout, validate, etc.
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, default='{}')
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.action} - {self.user} - {self.created_at}"


class UserProfile(models.Model):
    """Extended user profile for CAS users"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20, blank=True)
    department = models.CharField(max_length=100, blank=True)
    employee_id = models.CharField(max_length=50, blank=True)
    is_cas_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username} Profile"


class UserServiceAccess(models.Model):
    """Model to control user access to specific services"""
    ACCESS_TYPES = [
        ('ALLOW', 'Allow Access'),
        ('DENY', 'Deny Access'),
        ('PENDING', 'Pending Approval'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    access_type = models.CharField(max_length=10, choices=ACCESS_TYPES, default='PENDING')
    granted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='granted_access')
    granted_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True, help_text="Reason for granting/denying access")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['user', 'service']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.service.name} ({self.access_type})"
    
    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def can_access(self):
        """Check if user can access this service"""
        if not self.is_active:
            return False
        if self.is_expired():
            return False
        return self.access_type == 'ALLOW'


class ServiceGroup(models.Model):
    """Group services for easier access management"""
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    services = models.ManyToManyField(Service, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class UserGroupAccess(models.Model):
    """Model to control user access to service groups"""
    ACCESS_TYPES = [
        ('ALLOW', 'Allow Access'),
        ('DENY', 'Deny Access'),
        ('PENDING', 'Pending Approval'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service_group = models.ForeignKey(ServiceGroup, on_delete=models.CASCADE)
    access_type = models.CharField(max_length=10, choices=ACCESS_TYPES, default='PENDING')
    granted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='granted_group_access')
    granted_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['user', 'service_group']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.service_group.name} ({self.access_type})"
    
    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def can_access(self):
        """Check if user can access this service group"""
        if not self.is_active:
            return False
        if self.is_expired():
            return False
        return self.access_type == 'ALLOW'
