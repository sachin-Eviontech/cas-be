#!/usr/bin/env python3
"""
Example of how to integrate a service with the SERVICE-SPECIFIC token-based CAS system.

This example shows how a service can:
1. Redirect users to CAS for service-specific authentication
2. Validate service-specific JWT tokens from users
3. Extract user information from validated tokens
4. Handle token refresh and errors

IMPORTANT: This system is SERVICE-SPECIFIC - each service gets its own tokens
that can only be used with that specific service.
"""

import requests
import json
from typing import Dict, Optional, Tuple

# Configuration - CHANGE THESE FOR YOUR SERVICE
CAS_SERVER_URL = "http://localhost:8000"  # Your CAS server URL
SERVICE_URL = "https://myapp.example.com"  # YOUR service URL (must match exactly)


class CASServiceIntegration:
    """Helper class for integrating with SERVICE-SPECIFIC token-based CAS"""
    
    def __init__(self, cas_server_url: str, service_url: str):
        self.cas_server_url = cas_server_url.rstrip('/')
        self.service_url = service_url
        print(f"Initialized CAS integration for service: {service_url}")
    
    def get_login_url(self) -> str:
        """
        Get the CAS login URL for this service
        
        Returns:
            URL to redirect users for authentication
        """
        return f"{self.cas_server_url}/cas/token/?service={self.service_url}"
    
    def validate_service_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """
        Validate a service-specific JWT token with the CAS server
        
        Args:
            token: JWT token from user (must be for THIS service)
            
        Returns:
            Tuple of (is_valid, user_data)
        """
        try:
            response = requests.post(
                f"{self.cas_server_url}/api/token/validate/",
                json={
                    "token": token,
                    "service": self.service_url  # REQUIRED: Must match token's service
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return True, data
                else:
                    return False, None
            else:
                print(f"Token validation failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Error details: {error_data}")
                except:
                    pass
                return False, None
                
        except requests.RequestException as e:
            print(f"Error validating token: {e}")
            return False, None
    
    def refresh_token(self, refresh_token: str) -> Tuple[bool, Optional[str]]:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: JWT refresh token (must be for THIS service)
            
        Returns:
            Tuple of (success, new_access_token)
        """
        try:
            response = requests.post(
                f"{self.cas_server_url}/api/token/refresh/",
                json={
                    "refresh_token": refresh_token
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return True, data.get('access_token')
                else:
                    return False, None
            else:
                return False, None
                
        except requests.RequestException as e:
            print(f"Error refreshing token: {e}")
            return False, None
    
    def get_user_info(self, token: str) -> Optional[Dict]:
        """
        Get user information from service-specific token
        
        Args:
            token: JWT token from user (must be for THIS service)
            
        Returns:
            User information dict or None
        """
        try:
            response = requests.post(
                f"{self.cas_server_url}/api/token/user/",
                json={
                    "token": token,
                    "service": self.service_url  # REQUIRED: Must match token's service
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return {
                        'user': data.get('user'),
                        'service': data.get('service'),
                        'attributes': data.get('attributes')
                    }
            return None
                
        except requests.RequestException as e:
            print(f"Error getting user info: {e}")
            return None


def example_web_service_handler(request_data: Dict) -> Dict:
    """
    Example of how to handle a request in your web service with SERVICE-SPECIFIC tokens
    
    This would be called from your web framework (Flask, Django, FastAPI, etc.)
    """
    # Extract token from request
    # This could be from Authorization header, query parameter, or form data
    token = request_data.get('token') or request_data.get('authorization', '').replace('Bearer ', '')
    
    if not token:
        # Redirect to CAS login if no token provided
        cas = CASServiceIntegration(CAS_SERVER_URL, SERVICE_URL)
        return {
            'error': 'No token provided',
            'redirect_to': cas.get_login_url(),
            'status': 401
        }
    
    # Initialize CAS integration
    cas = CASServiceIntegration(CAS_SERVER_URL, SERVICE_URL)
    
    # Validate service-specific token
    is_valid, validation_data = cas.validate_service_token(token)
    if not is_valid:
        return {
            'error': 'Invalid, expired, or wrong-service token',
            'redirect_to': cas.get_login_url(),
            'status': 401
        }
    
    # Get user information (includes service validation)
    user_info = cas.get_user_info(token)
    if not user_info:
        return {
            'error': 'Could not retrieve user information',
            'status': 500
        }
    
    # Your service logic here
    return {
        'message': 'Welcome to the service!',
        'user': user_info['user'],
        'service': user_info['service'],
        'attributes': user_info['attributes'],
        'token_valid': True,
        'status': 200
    }


def example_api_endpoint():
    """
    Example of how to protect an API endpoint
    """
    # Simulate a request with token
    request_data = {
        'token': 'your-jwt-token-here',
        'other_data': 'some value'
    }
    
    result = example_web_service_handler(request_data)
    print(json.dumps(result, indent=2))


def example_redirect_flow():
    """
    Example of how to implement the SERVICE-SPECIFIC redirect flow for web login
    """
    cas = CASServiceIntegration(CAS_SERVER_URL, SERVICE_URL)
    
    print("=== SERVICE-SPECIFIC Token-Based Authentication Flow ===")
    print()
    print("1. User visits your service without token")
    print("2. Redirect to CAS server with YOUR service URL:")
    print(f"   {cas.get_login_url()}")
    print()
    print("3. User logs in and CAS checks if user has access to YOUR service")
    print("4. If access granted, user gets redirected back with SERVICE-SPECIFIC token:")
    print(f"   {SERVICE_URL}?token=JWT_TOKEN_FOR_THIS_SERVICE")
    print()
    print("5. Your service validates the token (which includes service verification)")
    print()
    print("=== IMPORTANT: Service-Specific Tokens ===")
    print()
    print("- Each service gets its own unique tokens")
    print("- Tokens can ONLY be used with the service they were created for")
    print("- Token validation automatically checks service match")
    print("- Users need separate tokens for each service they access")
    print()
    print("=== API Integration ===")
    print()
    print("For API calls, include token in Authorization header:")
    print("Authorization: Bearer JWT_SERVICE_SPECIFIC_TOKEN")
    print()
    print("Or as a query parameter:")
    print(f"{SERVICE_URL}/api/endpoint?token=JWT_SERVICE_SPECIFIC_TOKEN")
    print()
    print("=== Getting User's Available Services ===")
    print()
    print("To get list of services user can access:")
    print(f"POST {CAS_SERVER_URL}/api/user/services/")
    print("with username/password to see available services")


if __name__ == "__main__":
    example_redirect_flow()
    print("\n" + "="*50 + "\n")
    example_api_endpoint()
