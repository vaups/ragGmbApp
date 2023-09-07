# === IMPORTS ===

# Standard Libraries
import os
import logging

# Third-party Libraries
import flask
import requests
import redis
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import secrets
from flask_cors import CORS
from flask import Flask, request, session
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
import json

# === CONFIGURATION ===

logging.basicConfig(level=logging.DEBUG)

# ENV Variables
CLIENT_SECRETS_FILE = os.environ.get('CLIENT_SECRETS_FILE')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
AUTH_URI = os.environ.get('AUTH_URI')
TOKEN_URI = os.environ.get('TOKEN_URI')
AUTH_PROVIDER_X509_CERT_URL = os.environ.get('AUTH_PROVIDER_X509_CERT_URL')
REDIRECT_URIS = os.environ.get('REDIRECT_URIS').split(",")

# Dictionary of Locations for GMB
LOCATIONS = {
    "Reed Jeep Chrysler Dodge Ram of Kansas City Service Center": ("107525660123223074874", "6602925040958900944"),
    "Reed Jeep of Kansas City": ("107525660123223074874", "1509419292313302599"),
    "Reed Jeep Chrysler Dodge Ram of Kansas City Parts Store": ("107525660123223074874", "13301160076946238237"),
    "Reed Chrysler Dodge Jeep Ram": ("111693813506330378362", "11797626926263627465"),
    "Reed Jeep Ram Service Center of St. Joseph": ("111693813506330378362", "14280468831929260325"),
    "Reed Jeep Ram Parts Store": ("111693813506330378362", "2418643850076402830"),
    "Reed Hyundai St. Joseph": ("106236436844097816145", "11886236645408970450"),
    "Reed Hyundai Service Center St. Joseph": ("106236436844097816145", "14394473597121013675"),
    "Reed Hyundai of Kansas City": ("109745744288166151974", "8949845982319380160"),
    "Reed Hyundai Service Center of Kansas City": ("109745744288166151974", "14191266722711425624"),
    "Reed Hyundai Parts Store": ("109745744288166151974", "16832194732739486696"),
    "Reed Collision Center": ("118020935772003776996", "14476819248161239911"),
    "Reed Chevrolet of St Joseph": ("101540168465155832676", "4906344306812977154"),
    "Reed Chevrolet Service Center": ("101540168465155832676", "7432353734414121407"),
    "Reed Chevrolet Parts": ("101540168465155832676", "13264330561216148213"),
    "Reed Buick GMC, INC.": ("109231983509135903650", "9980434767027047433"),
    "Reed Buick GMC Service Center": ("109231983509135903650", "9597638825461585665"),
    "Reed Buick GMC Collision Center": ("109231983509135903650", "10315051056232587965")
}

# Google API Config
SCOPES = ["https://www.googleapis.com/auth/business.manage"]
API_SERVICE_NAME = 'mybusiness'
API_VERSION = 'v4'

# === APP INITIALIZATION ===

app = flask.Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://app.gmb.reedauto.com"])
app.wsgi_app = ProxyFix(app.wsgi_app)

# App Secret
if 'SECRET_KEY' in os.environ:
    app.secret_key = os.environ['SECRET_KEY']
else:
    raise ValueError("No SECRET_KEY set for Flask application. Set this environment variable.")

# Redis Session Configuration
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_REDIS'] = redis.StrictRedis(host='srv-captain--redis', port=6379, db=0, password=os.environ.get('REDIS_PASSWORD'))
app.config['SESSION_COOKIE_DOMAIN'] = '.reedauto.com'
app.config['SESSION_COOKIE_PATH'] = '/'
Session(app)

redis_client = redis.StrictRedis(host='srv-captain--redis', port=6379, db=0, password=os.environ.get('REDIS_PASSWORD'))


def generate_random_string(length):
    return secrets.token_hex(length)

# === ROUTES ===

@app.route('/')
def index():
    """Home route to start the authentication flow."""
    return '''
        <html>
            <head>
                <title>Google My Business API Integration</title>
            </head>
            <body>
                <h2>Welcome to the Google My Business API Integration</h2>
                <p>Click the button below to start the authentication flow:</p>
                <button onclick="location.href='/authorize'" type="button">Start Authentication</button>
            </body>
        </html>
    '''

@app.route('/set/')
def set_session_value():
    """Test route to set a session value."""
    session['key'] = 'value'
    return 'Key set.'

@app.route('/get/')
def get_session_value():
    """Test route to retrieve a session value."""
    return session.get('key', 'Not set')

@app.route('/authorize')
def authorize():
    """Begin the Google OAuth2 authorization flow."""
    redis_client = redis.StrictRedis(host='srv-captain--redis', port=6379, db=0, password=os.environ.get('REDIS_PASSWORD'))

    state = generate_random_string(32)
    redis_client.set('state', state)

    next_page = flask.request.args.get('next', 'https://app.gmb.reedauto.com/')
    app.logger.debug(f"Setting next_page to {next_page}")
    flask.session['next_page'] = next_page

    client_config = {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": AUTH_URI,
            "token_uri": TOKEN_URI,
            "auth_provider_x509_cert_url": AUTH_PROVIDER_X509_CERT_URL,
            "redirect_uris": REDIRECT_URIS
        }
    }
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True, _scheme='https')

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='false',
        state=state
    )

    return flask.jsonify({"authorization_url": authorization_url})

@app.route('/oauth2callback')
def oauth2callback():
    # Retrieve state from Redis and validate
    stored_state = redis_client.get('state')
    if stored_state is not None:
        stored_state = stored_state.decode()
    url_state = flask.request.args.get('state')

    if stored_state is None or stored_state != url_state:
        app.logger.error("Invalid state")
        return "Invalid state", 400

    # Initialize the same OAuth2 flow as in /authorize
    client_config = {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": AUTH_URI,
            "token_uri": TOKEN_URI,
            "auth_provider_x509_cert_url": AUTH_PROVIDER_X509_CERT_URL,
            "redirect_uris": REDIRECT_URIS
        }
    }

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config, scopes=SCOPES, state=stored_state)
    flow.redirect_uri = 'https://backend.gmb.reedauto.com/oauth2callback'

    # Now, use the authorization_response to fetch the access token
    authorization_response = flask.request.url
    try:
        flow.fetch_token(authorization_response=authorization_response)
    except Exception as e:
        app.logger.error(f"Exception occurred: {e}")
        app.logger.exception("Exception details:")
        return f"Error: {e}", 500

    # Store credentials in session
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)
    flask.session['access_token'] = credentials.token  # Store the access token here

    # Delete the state in Redis to complete the flow
    redis_client.delete('state')

    # Redirect to the original destination
    next_page = flask.session.get('next_page', 'https://app.gmb.reedauto.com/')
    app.logger.debug(f"Next page from session: {next_page}")

    return flask.redirect(next_page)

    
@app.route('/fetch_reviews', methods=['GET'])
def fetch_reviews():
    try:
        location_name = request.args.get('location_name')
        if not location_name or location_name not in LOCATIONS:
            return flask.jsonify({"error": "Invalid location name"}), 400

        account_id, location_id = LOCATIONS[location_name]

        if 'credentials' not in flask.session:
            return flask.redirect('authorize')

        credentials = google.oauth2.credentials.Credentials(
            **flask.session['credentials'])

        # Check for token expiry and refresh if necessary
        if credentials.expired:
            credentials.refresh(request)

        with open('mybusiness_google_rest_v4p9.json', 'r') as f:
            discovery_service = f.read()

        service = googleapiclient.discovery.build_from_document(
            discovery_service, credentials=credentials)

        response = service.accounts().locations().reviews().list(
            parent=f'accounts/{account_id}/locations/{location_id}'
        ).execute()

        reviews = response.get('reviews', [])
        flask.session['credentials'] = credentials_to_dict(credentials)
        app.logger.debug(f"Sending reviews: {json.dumps(reviews)}")
        return flask.jsonify(reviews)

    except Exception as e:
        app.logger.error(f"Exception occurred: {e}")
        app.logger.exception("Exception details:")
        return flask.jsonify({"error": str(e)}), 500

@app.route('/check_auth')
def check_auth():
    if 'credentials' in flask.session:
        access_token = flask.session.get('access_token')
        return flask.jsonify({"isAuthenticated": True, "access_token": access_token})
    else:
        return flask.jsonify({"isAuthenticated": False})
    
@app.route('/test_redis')
def test_redis():
    """Test route to set a key in Redis and then retrieve it."""
    try:
        # Connect to Redis
        r = app.config['SESSION_REDIS']

        # Set a key
        key_name = "test_key"
        value = "Hello, Redis!"
        r.set(key_name, value)

        # Retrieve the key
        retrieved_value = r.get(key_name)

        # Clean up (optional)
        r.delete(key_name)

        return f"Set {key_name} to {value}. Retrieved value: {retrieved_value}"
    except Exception as e:
        return f"Error: {e}", 500

# === UTILITY FUNCTIONS ===

def credentials_to_dict(credentials):
    """Convert Google OAuth2 credentials to a dictionary."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# === MAIN EXECUTION ===

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
