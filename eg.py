# -*- coding: utf-8 -*-

import os
import flask
import requests
import redis
import logging

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from flask_cors import CORS
from flask import request
from flask_session import Session

logging.basicConfig(level=logging.DEBUG)

# Use environment variable for client secrets file or default to 'client_secret.json'
CLIENT_SECRETS_FILE = os.environ.get('CLIENT_SECRETS_FILE', 'client_secret.json')

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

SCOPES = [
    "https://www.googleapis.com/auth/business.manage"
]
API_SERVICE_NAME = 'mybusiness'
API_VERSION = 'v4'

app = flask.Flask(__name__)
CORS(app) #allow all origins
if 'SECRET_KEY' in os.environ:
    app.secret_key = os.environ['SECRET_KEY']
else:
    raise ValueError("No SECRET_KEY set for Flask application. Set this environment variable.")

# Configure server-side sessions
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'gmb:'
app.config['SESSION_REDIS'] = redis.StrictRedis(host='localhost', port=6379, db=0)  # Adjust as per your Redis configuration

Session(app)

@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    flask.session['state'] = state

    return flask.jsonify({"authorization_url": authorization_url})


@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session.get('state')
    url_state = flask.request.args.get('state')

    app.logger.debug(f"State from session: {state}")
    app.logger.debug(f"State from URL: {url_state}")

    if state != url_state:
        app.logger.error("State mismatch error!")
        print("State from session:", state)
        print("State from URL:", url_state)
        return "State mismatch error!", 400

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_response = flask.request.url
    try:
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        flask.session['credentials'] = credentials_to_dict(credentials)
    except Exception as e:
        app.logger.error(f"Error fetching token: {e}")
        return f"Error: {e}", 500

    if 'credentials' in flask.session:
        return flask.jsonify({"status": "success"})
    else:
        return flask.jsonify({"status": "error", "message": "Error fetching token"})


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

@app.route('/')
def index():
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

@app.route('/fetch_reviews', methods=['GET'])
def fetch_reviews():
    location_name = request.args.get('location_name')
    if not location_name or location_name not in LOCATIONS:
        return flask.jsonify({"error": "Invalid location name"}), 400

    account_id, location_id = LOCATIONS[location_name]

    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    # Use the local discovery document
    with open('mybusiness_google_rest_v4p9.json', 'r') as f:
        discovery_service = f.read()

    service = googleapiclient.discovery.build_from_document(
        discovery_service, credentials=credentials)

    try:
        response = service.accounts().locations().reviews().list(
            parent=f'accounts/{account_id}/locations/{location_id}'
        ).execute()
        reviews = response.get('reviews', [])
        flask.session['credentials'] = credentials_to_dict(credentials)
        return flask.jsonify(reviews)
    except Exception as e:
        print(f"Error fetching reviews {e}")
        return f"Error: {e}", 500

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
