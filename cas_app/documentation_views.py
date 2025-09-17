from django.http import JsonResponse
from django.views import View
from django.urls import reverse
from django.conf import settings


class APIDocumentationView(View):
    """Custom API documentation view"""
    
    def get(self, request):
        """Return comprehensive API documentation"""
        base_url = request.build_absolute_uri('/api/')
        
        documentation = {
            'title': 'CAS Server API Documentation',
            'version': '1.0.0',
            'description': 'Central Authentication Service API for managing user access to websites and services',
            'base_url': base_url,
            'authentication': {
                'type': 'Session-based and Token-based',
                'session': 'Use Django session authentication for web interface',
                'token': 'Use Token authentication for API access',
                'login_endpoint': f'{base_url}auth/login/',
                'logout_endpoint': f'{base_url}auth/logout/',
            },
            'endpoints': {
                'authentication': {
                    'login': {
                        'url': f'{base_url}auth/login/',
                        'method': 'POST',
                        'description': 'Authenticate user and optionally generate service ticket',
                        'parameters': {
                            'username': 'string (required)',
                            'password': 'string (required)',
                            'service': 'string (optional) - URL of requesting service',
                            'remember_me': 'boolean (optional)'
                        },
                        'response': {
                            'success': 'boolean',
                            'user': 'object - user information',
                            'ticket': 'string (if service provided)',
                            'message': 'string'
                        }
                    },
                    'logout': {
                        'url': f'{base_url}auth/logout/',
                        'method': 'POST',
                        'description': 'Logout current user',
                        'authentication': 'required',
                        'response': {
                            'success': 'boolean',
                            'message': 'string'
                        }
                    },
                    'validate': {
                        'url': f'{base_url}auth/validate/',
                        'method': 'POST',
                        'description': 'Validate CAS ticket',
                        'parameters': {
                            'ticket': 'string (required)',
                            'service': 'string (required)',
                            'pgtUrl': 'string (optional)'
                        },
                        'response': {
                            'success': 'boolean',
                            'user': 'string - username',
                            'attributes': 'object - user attributes',
                            'pgt': 'string (if pgtUrl provided)'
                        }
                    },
                    'user_info': {
                        'url': f'{base_url}auth/user/',
                        'method': 'GET',
                        'description': 'Get current user information',
                        'authentication': 'required',
                        'response': {
                            'user': 'object - user information',
                            'profile': 'object - user profile'
                        }
                    }
                },
                'service_management': {
                    'list_services': {
                        'url': f'{base_url}services/',
                        'method': 'GET',
                        'description': 'List all registered services',
                        'authentication': 'admin required',
                        'response': 'array of service objects'
                    },
                    'create_service': {
                        'url': f'{base_url}services/',
                        'method': 'POST',
                        'description': 'Register new service',
                        'authentication': 'admin required',
                        'parameters': {
                            'name': 'string (required)',
                            'url': 'string (required) - callback URL',
                            'description': 'string (optional)',
                            'is_active': 'boolean (optional, default: true)'
                        }
                    },
                    'service_detail': {
                        'url': f'{base_url}services/<id>/',
                        'method': 'GET/PUT/DELETE',
                        'description': 'Get, update, or delete service',
                        'authentication': 'admin required'
                    }
                },
                'access_management': {
                    'accessible_services': {
                        'url': f'{base_url}access/accessible-services/',
                        'method': 'GET',
                        'description': 'Get all services user has access to',
                        'authentication': 'required',
                        'response': {
                            'accessible_services': 'array of service objects with access info',
                            'count': 'number'
                        }
                    },
                    'request_access': {
                        'url': f'{base_url}access/request/',
                        'method': 'POST',
                        'description': 'Request access to service or service group',
                        'authentication': 'required',
                        'parameters': {
                            'service_id': 'number (optional)',
                            'service_group_id': 'number (optional)',
                            'reason': 'string (optional)'
                        },
                        'response': {
                            'success': 'boolean',
                            'message': 'string',
                            'access_id': 'number'
                        }
                    },
                    'approve_access': {
                        'url': f'{base_url}access/approve/',
                        'method': 'POST',
                        'description': 'Approve or deny access request',
                        'authentication': 'admin required',
                        'parameters': {
                            'access_id': 'number (required)',
                            'access_type': 'string (required) - ALLOW or DENY',
                            'reason': 'string (optional)',
                            'expires_at': 'datetime (optional)'
                        }
                    },
                    'pending_requests': {
                        'url': f'{base_url}access/pending/',
                        'method': 'GET',
                        'description': 'Get all pending access requests',
                        'authentication': 'admin required',
                        'response': {
                            'service_requests': 'array of service access requests',
                            'group_requests': 'array of group access requests',
                            'total_pending': 'number'
                        }
                    },
                    'check_access': {
                        'url': f'{base_url}access/check/<service_url>/',
                        'method': 'GET',
                        'description': 'Check if user has access to specific service',
                        'authentication': 'required',
                        'response': {
                            'has_access': 'boolean',
                            'message': 'string',
                            'service_url': 'string'
                        }
                    }
                },
                'service_groups': {
                    'list_groups': {
                        'url': f'{base_url}service-groups/',
                        'method': 'GET',
                        'description': 'List all service groups',
                        'authentication': 'admin required'
                    },
                    'create_group': {
                        'url': f'{base_url}service-groups/',
                        'method': 'POST',
                        'description': 'Create new service group',
                        'authentication': 'admin required',
                        'parameters': {
                            'name': 'string (required)',
                            'description': 'string (optional)',
                            'services': 'array of service IDs (optional)',
                            'is_active': 'boolean (optional, default: true)'
                        }
                    },
                    'group_detail': {
                        'url': f'{base_url}service-groups/<id>/',
                        'method': 'GET/PUT/DELETE',
                        'description': 'Get, update, or delete service group',
                        'authentication': 'admin required'
                    }
                },
                'user_data': {
                    'tickets': {
                        'url': f'{base_url}tickets/',
                        'method': 'GET',
                        'description': 'Get user\'s authentication tickets',
                        'authentication': 'required'
                    },
                    'logs': {
                        'url': f'{base_url}logs/',
                        'method': 'GET',
                        'description': 'Get user\'s authentication logs',
                        'authentication': 'required'
                    },
                    'profile': {
                        'url': f'{base_url}profile/',
                        'method': 'GET/PUT',
                        'description': 'Get or update user profile',
                        'authentication': 'required'
                    }
                },
                'admin': {
                    'stats': {
                        'url': f'{base_url}admin/stats/',
                        'method': 'GET',
                        'description': 'Get CAS server statistics',
                        'authentication': 'admin required',
                        'response': {
                            'total_users': 'number',
                            'active_users': 'number',
                            'total_services': 'number',
                            'active_services': 'number',
                            'total_tickets': 'number',
                            'valid_tickets': 'number',
                            'recent_logins': 'number'
                        }
                    }
                }
            },
            'cas_protocol': {
                'description': 'Standard CAS protocol endpoints for website integration',
                'login': {
                    'url': '/cas/login/',
                    'description': 'CAS login page with service parameter',
                    'usage': '/cas/login/?service=<your-callback-url>'
                },
                'logout': {
                    'url': '/cas/logout/',
                    'description': 'CAS logout with optional service parameter',
                    'usage': '/cas/logout/?service=<your-website-url>'
                },
                'service_validate': {
                    'url': '/cas/serviceValidate/',
                    'description': 'Validate service ticket (XML response)',
                    'usage': '/cas/serviceValidate/?ticket=<ticket>&service=<service-url>'
                },
                'validate': {
                    'url': '/cas/validate/',
                    'description': 'Validate service ticket (JSON response)',
                    'usage': '/cas/validate/?ticket=<ticket>&service=<service-url>'
                },
                'proxy_validate': {
                    'url': '/cas/proxyValidate/',
                    'description': 'Validate proxy ticket',
                    'usage': '/cas/proxyValidate/?ticket=<ticket>&service=<service-url>'
                }
            },
            'examples': {
                'website_integration': {
                    'description': 'How to integrate CAS with your website',
                    'steps': [
                        '1. Register your website as a service in CAS admin',
                        '2. Redirect unauthenticated users to: /cas/login/?service=<your-callback-url>',
                        '3. Handle callback with ticket parameter',
                        '4. Validate ticket with CAS server',
                        '5. Grant access if validation succeeds'
                    ],
                    'example_code': '''
# Example Flask integration
@app.route('/login')
def login():
    service_url = f"{request.url_root}callback"
    cas_url = f"{CAS_SERVER}/cas/login/?service={service_url}"
    return redirect(cas_url)

@app.route('/callback')
def callback():
    ticket = request.args.get('ticket')
    if ticket:
        # Validate ticket with CAS
        validate_url = f"{CAS_SERVER}/cas/serviceValidate/"
        params = {'ticket': ticket, 'service': request.url_root + 'callback'}
        response = requests.get(validate_url, params=params)
        # Parse XML response and grant access
                    '''
                },
                'api_usage': {
                    'authentication': '''
# Login via API
POST /api/auth/login/
{
    "username": "john.doe",
    "password": "password123",
    "service": "http://mywebsite.com/callback"
}

# Response
{
    "success": true,
    "user": {...},
    "ticket": "ST-1234567890"
}
                    ''',
                    'check_access': '''
# Check if user has access to service
GET /api/access/check/http://mywebsite.com/callback/

# Response
{
    "has_access": true,
    "message": "Access granted",
    "service_url": "http://mywebsite.com/callback/"
}
                    '''
                }
            },
            'error_codes': {
                '400': 'Bad Request - Invalid parameters',
                '401': 'Unauthorized - Authentication required',
                '403': 'Forbidden - Insufficient permissions',
                '404': 'Not Found - Resource not found',
                '500': 'Internal Server Error - Server error'
            }
        }
        
        return JsonResponse(documentation, json_dumps_params={'indent': 2})


class APISchemaView(View):
    """API Schema view for OpenAPI/Swagger documentation"""
    
    def get(self, request):
        """Return OpenAPI schema"""
        schema = {
            'openapi': '3.0.0',
            'info': {
                'title': 'CAS Server API',
                'version': '1.0.0',
                'description': 'Central Authentication Service API'
            },
            'servers': [
                {
                    'url': request.build_absolute_uri('/api/'),
                    'description': 'CAS Server API'
                }
            ],
            'paths': {
                '/auth/login/': {
                    'post': {
                        'summary': 'User Login',
                        'description': 'Authenticate user and optionally generate service ticket',
                        'requestBody': {
                            'required': True,
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'properties': {
                                            'username': {'type': 'string'},
                                            'password': {'type': 'string'},
                                            'service': {'type': 'string', 'format': 'uri'},
                                            'remember_me': {'type': 'boolean'}
                                        },
                                        'required': ['username', 'password']
                                    }
                                }
                            }
                        },
                        'responses': {
                            '200': {
                                'description': 'Login successful',
                                'content': {
                                    'application/json': {
                                        'schema': {
                                            'type': 'object',
                                            'properties': {
                                                'success': {'type': 'boolean'},
                                                'user': {'type': 'object'},
                                                'ticket': {'type': 'string'},
                                                'message': {'type': 'string'}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return JsonResponse(schema, json_dumps_params={'indent': 2})
