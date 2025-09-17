from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import (
    Service, Ticket, ProxyGrantingTicket, AuthenticationLog, UserProfile,
    UserServiceAccess, ServiceGroup, UserGroupAccess
)


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'


class CustomUserAdmin(UserAdmin):
    inlines = (UserProfileInline,)


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ['name', 'url', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'url', 'description']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ['ticket_id', 'ticket_type', 'user', 'service', 'is_used', 'is_valid', 'created_at', 'expires_at']
    list_filter = ['ticket_type', 'is_used', 'is_valid', 'created_at']
    search_fields = ['ticket_id', 'user__username', 'service__name']
    readonly_fields = ['ticket_id', 'created_at']


@admin.register(ProxyGrantingTicket)
class ProxyGrantingTicketAdmin(admin.ModelAdmin):
    list_display = ['pgt_id', 'user', 'is_used', 'is_valid', 'created_at', 'expires_at']
    list_filter = ['is_used', 'is_valid', 'created_at']
    search_fields = ['pgt_id', 'user__username']
    readonly_fields = ['pgt_id', 'created_at']


@admin.register(AuthenticationLog)
class AuthenticationLogAdmin(admin.ModelAdmin):
    list_display = ['action', 'user', 'service', 'ip_address', 'success', 'created_at']
    list_filter = ['action', 'success', 'created_at']
    search_fields = ['user__username', 'service__name', 'ip_address']
    readonly_fields = ['created_at']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'department', 'employee_id', 'is_cas_admin', 'created_at']
    list_filter = ['is_cas_admin', 'department', 'created_at']
    search_fields = ['user__username', 'employee_id', 'department']


@admin.register(UserServiceAccess)
class UserServiceAccessAdmin(admin.ModelAdmin):
    list_display = ['user', 'service', 'access_type', 'is_active', 'granted_at', 'expires_at', 'created_at']
    list_filter = ['access_type', 'is_active', 'created_at', 'service']
    search_fields = ['user__username', 'service__name', 'reason']
    readonly_fields = ['created_at', 'updated_at']
    raw_id_fields = ['user', 'service', 'granted_by']
    
    def save_model(self, request, obj, form, change):
        if not change and not obj.granted_by:
            obj.granted_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(ServiceGroup)
class ServiceGroupAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_active', 'service_count', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at']
    filter_horizontal = ['services']
    
    def service_count(self, obj):
        return obj.services.count()
    service_count.short_description = 'Services Count'


@admin.register(UserGroupAccess)
class UserGroupAccessAdmin(admin.ModelAdmin):
    list_display = ['user', 'service_group', 'access_type', 'is_active', 'granted_at', 'expires_at', 'created_at']
    list_filter = ['access_type', 'is_active', 'created_at', 'service_group']
    search_fields = ['user__username', 'service_group__name', 'reason']
    readonly_fields = ['created_at', 'updated_at']
    raw_id_fields = ['user', 'service_group', 'granted_by']
    
    def save_model(self, request, obj, form, change):
        if not change and not obj.granted_by:
            obj.granted_by = request.user
        super().save_model(request, obj, form, change)


# Unregister the default User admin and register our custom one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
