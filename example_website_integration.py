#!/usr/bin/env python3
"""
Example website integration with CAS Server
This demonstrates how a website can integrate with your CAS system for authentication.
"""

import requests
import json
from urllib.parse import urlencode, parse_qs, urlparse
from flask import Flask, request, redirect, session, render_template_string, jsonify

# CAS Server configuration
CAS_SERVER_URL = "http://localhost:8000"
CAS_LOGIN_URL = f"{CAS_SERVER_URL}/cas/login"
CAS_VALIDATE_URL = f"{CAS_SERVER_URL}/cas/serviceValidate"
CAS_LOGOUT_URL = f"{CAS_SERVER_URL}/cas/logout"

# Your website configuration
WEBSITE_URL = "http://localhost:5000"
WEBSITE_NAME = "Example Website"

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# HTML template for the example website
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ website_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .content { margin: 20px 0; }
        .user-info { background: #e8f5e8; padding: 15px; border-radius: 5px; }
        .logout-btn { background: #ff6b6b; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .login-btn { background: #4ecdc4; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ website_name }}</h1>
        {% if user %}
            <p>Welcome, {{ user.username }}!</p>
        {% else %}
            <p>Please log in to access this website.</p>
        {% endif %}
    </div>
    
    <div class="content">
        {% if user %}
            <div class="user-info">
                <h3>User Information:</h3>
                <p><strong>Username:</strong> {{ user.username }}</p>
                <p><strong>Email:</strong> {{ user.email }}</p>
                <p><strong>Name:</strong> {{ user.first_name }} {{ user.last_name }}</p>
                {% if user.department %}
                    <p><strong>Department:</strong> {{ user.department }}</p>
                {% endif %}
                {% if user.employee_id %}
                    <p><strong>Employee ID:</strong> {{ user.employee_id }}</p>
                {% endif %}
            </div>
            
            <h3>Protected Content</h3>
            <p>This content is only visible to authenticated users with access to this website.</p>
            
            <form method="post" action="/logout">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        {% else %}
            <p>This website is protected by CAS authentication.</p>
            <p>Click the button below to log in:</p>
            <a href="/login" class="login-btn">Login with CAS</a>
        {% endif %}
    </div>
</body>
</html>
"""


def validate_ticket_with_cas(ticket, service_url):
    """
    Validate a CAS ticket with the CAS server
    """
    try:
        # Prepare validation request
        params = {
            'ticket': ticket,
            'service': service_url
        }
        
        # Make request to CAS server
        response = requests.get(CAS_VALIDATE_URL, params=params, timeout=10)
        
        if response.status_code == 200:
            # Parse XML response
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.text)
            
            # Check for authentication success
            success_elem = root.find('.//{http://www.yale.edu/tp/cas}authenticationSuccess')
            if success_elem is not None:
                user_elem = success_elem.find('{http://www.yale.edu/tp/cas}user')
                if user_elem is not None:
                    username = user_elem.text
                    
                    # Get user attributes if available
                    attributes = {}
                    attrs_elem = success_elem.find('{http://www.yale.edu/tp/cas}attributes')
                    if attrs_elem is not None:
                        for attr in attrs_elem:
                            tag = attr.tag.replace('{http://www.yale.edu/tp/cas}', '')
                            attributes[tag] = attr.text
                    
                    return True, username, attributes
            
            # Check for authentication failure
            failure_elem = root.find('.//{http://www.yale.edu/tp/cas}authenticationFailure')
            if failure_elem is not None:
                error_code = failure_elem.get('code', 'UNKNOWN')
                error_message = failure_elem.text
                return False, f"Authentication failed: {error_code} - {error_message}", None
        
        return False, "Invalid response from CAS server", None
        
    except requests.RequestException as e:
        return False, f"Network error: {str(e)}", None
    except Exception as e:
        return False, f"Validation error: {str(e)}", None


@app.route('/')
def index():
    """Main page - show user info if authenticated"""
    user = session.get('user')
    return render_template_string(HTML_TEMPLATE, 
                                website_name=WEBSITE_NAME, 
                                user=user)


@app.route('/login')
def login():
    """Redirect to CAS login"""
    # Create service URL for this website
    service_url = f"{WEBSITE_URL}/callback"
    
    # Redirect to CAS login with service parameter
    cas_login_url = f"{CAS_LOGIN_URL}?service={service_url}"
    return redirect(cas_login_url)


@app.route('/callback')
def callback():
    """Handle callback from CAS after authentication"""
    ticket = request.args.get('ticket')
    
    if not ticket:
        return "Error: No ticket provided", 400
    
    # Validate ticket with CAS server
    service_url = f"{WEBSITE_URL}/callback"
    success, result, attributes = validate_ticket_with_cas(ticket, service_url)
    
    if success:
        # Store user info in session
        user_info = {
            'username': result,
            'email': attributes.get('email', ''),
            'first_name': attributes.get('firstName', ''),
            'last_name': attributes.get('lastName', ''),
            'department': attributes.get('department', ''),
            'employee_id': attributes.get('employee_id', ''),
        }
        session['user'] = user_info
        session['authenticated'] = True
        
        return redirect('/')
    else:
        return f"Authentication failed: {result}", 400


@app.route('/logout', methods=['POST'])
def logout():
    """Logout and redirect to CAS logout"""
    # Clear session
    session.clear()
    
    # Redirect to CAS logout
    return redirect(CAS_LOGOUT_URL)


@app.route('/api/user')
def api_user():
    """API endpoint to get current user info"""
    user = session.get('user')
    if user:
        return jsonify({
            'authenticated': True,
            'user': user
        })
    else:
        return jsonify({
            'authenticated': False,
            'user': None
        }), 401


if __name__ == '__main__':
    print(f"Starting {WEBSITE_NAME}...")
    print(f"Website URL: {WEBSITE_URL}")
    print(f"CAS Server: {CAS_SERVER_URL}")
    print("\nTo test the integration:")
    print("1. Start your CAS server: python manage.py runserver")
    print("2. Register this website as a service in CAS admin")
    print("3. Start this example: python example_website_integration.py")
    print("4. Visit http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
