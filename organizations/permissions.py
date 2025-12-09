from rest_framework.permissions import BasePermission

class CanCreateOrganizations(BasePermission):
    def has_permission(self,request,view):
        return request.user.has_perm('organizations.add_organization')
    
class CanViewOrganizations(BasePermission):
    def has_permission(self,request,view):
        return request.user.has_perm('organizations.view_organization')
    
class CanUpdateOrganizations(BasePermission):
    def has_permission(self,request,view):
        return request.user.has_perm('organizations.change_organization')
    
class CanDeleteOrganizations(BasePermission):
    def has_permission(self,request,view):
        return request.user.has_perm('organizations.delete_organization')
    
    