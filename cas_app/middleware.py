from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
import re


class CSRFExemptAPIMiddleware(MiddlewareMixin):
    """
    Middleware to exempt API endpoints from CSRF protection
    """
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Check if the request is for an API endpoint
        if request.path.startswith('/api/'):
            # Set CSRF exempt flag
            request._dont_enforce_csrf_checks = True
        return None
