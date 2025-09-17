from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Service, Ticket, ProxyGrantingTicket, AuthenticationLog, UserProfile,
    UserServiceAccess, ServiceGroup, UserGroupAccess
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'date_joined']
        read_only_fields = ['id', 'date_joined']


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'phone_number', 'department', 'employee_id', 'is_cas_admin', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['id', 'name', 'url', 'description', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class TicketSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service = ServiceSerializer(read_only=True)
    
    class Meta:
        model = Ticket
        fields = ['ticket_id', 'ticket_type', 'user', 'service', 'created_at', 'expires_at', 'is_used', 'is_valid']
        read_only_fields = ['ticket_id', 'created_at']


class ProxyGrantingTicketSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = ProxyGrantingTicket
        fields = ['pgt_id', 'user', 'created_at', 'expires_at', 'is_used', 'is_valid']
        read_only_fields = ['pgt_id', 'created_at']


class AuthenticationLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service = ServiceSerializer(read_only=True)
    
    class Meta:
        model = AuthenticationLog
        fields = ['id', 'user', 'service', 'action', 'ip_address', 'user_agent', 'success', 'created_at', 'details']
        read_only_fields = ['id', 'created_at']


class LoginRequestSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)
    service = serializers.URLField(required=False)
    remember_me = serializers.BooleanField(default=False)


class LogoutRequestSerializer(serializers.Serializer):
    service = serializers.URLField(required=False)


class ValidateRequestSerializer(serializers.Serializer):
    ticket = serializers.CharField(max_length=255)
    service = serializers.URLField()
    pgtUrl = serializers.URLField(required=False)


class UserServiceAccessSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service = ServiceSerializer(read_only=True)
    granted_by = UserSerializer(read_only=True)
    
    class Meta:
        model = UserServiceAccess
        fields = [
            'id', 'user', 'service', 'access_type', 'granted_by', 'granted_at',
            'expires_at', 'reason', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ServiceGroupSerializer(serializers.ModelSerializer):
    services = ServiceSerializer(many=True, read_only=True)
    service_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ServiceGroup
        fields = ['id', 'name', 'description', 'services', 'service_count', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_service_count(self, obj):
        return obj.services.count()


class UserGroupAccessSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service_group = ServiceGroupSerializer(read_only=True)
    granted_by = UserSerializer(read_only=True)
    
    class Meta:
        model = UserGroupAccess
        fields = [
            'id', 'user', 'service_group', 'access_type', 'granted_by', 'granted_at',
            'expires_at', 'reason', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class AccessRequestSerializer(serializers.Serializer):
    """Serializer for requesting access to services"""
    service_id = serializers.IntegerField(required=False)
    service_group_id = serializers.IntegerField(required=False)
    reason = serializers.CharField(max_length=500, required=False)
    
    def validate(self, data):
        if not data.get('service_id') and not data.get('service_group_id'):
            raise serializers.ValidationError("Either service_id or service_group_id is required")
        return data


class AccessApprovalSerializer(serializers.Serializer):
    """Serializer for approving/denying access requests"""
    access_id = serializers.IntegerField()
    access_type = serializers.ChoiceField(choices=['ALLOW', 'DENY'])
    reason = serializers.CharField(max_length=500, required=False)
    expires_at = serializers.DateTimeField(required=False)
