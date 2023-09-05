# === IMPORTS ===

# Standard Libraries
import os
import logging
import json
from flask import jsonify

# Third-party Libraries
import flask
import redis
from google.oauth2.service_account import Credentials
import googleapiclient.discovery
import secrets
from flask_cors import CORS, cross_origin
from flask import Flask, request, session
from flask_session import Session

# === CONFIGURATION ===
logging.basicConfig(level=logging.DEBUG)

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

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://app.gmb.reedauto.com/"}})  # Update this to your frontend domain

# Load the service account credentials
with open("sa_secret.json", "r") as f:
    SERVICE_ACCOUNT_INFO = json.load(f)

# Initialize the service account credentials
credentials = Credentials.from_service_account_info(
    SERVICE_ACCOUNT_INFO,
    scopes=SCOPES
)

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


# === UTILITY FUNCTIONS ===

def generate_random_string(length):
    return secrets.token_hex(length)

# === ROUTES ===


@app.route('/')
def index():
    return 'Welcome to the Google My Business API Integration'

@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Replace with your actual authentication logic
    if username == "your_username" and password == "your_password":
        session['is_authenticated'] = True
        return jsonify({"message": "Logged in successfully"}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/fetch_reviews', methods=['GET'])
@cross_origin()
def fetch_reviews():
    if not session.get('is_authenticated'):
        return jsonify({"message": "Not authenticated"}), 401

    location_name = request.args.get('location_name')
    if not location_name or location_name not in LOCATIONS:
        return jsonify({"error": "Invalid location name"}), 400

    account_id, location_id = LOCATIONS[location_name]

    # Use the local discovery document
    with open('mybusiness_google_rest_v4p9.json', 'r') as f:
        discovery_service = f.read()

    service = googleapiclient.discovery.build_from_document(
        discovery_service, credentials=credentials
    )

    try:
        response = service.accounts().locations().reviews().list(
            parent=f'accounts/{account_id}/locations/{location_id}'
        ).execute()
        reviews = response.get('reviews', [])
        return jsonify(reviews)
    except Exception as e:
        print(f"Error fetching reviews {e}")
        return f"Error: {e}", 500

# === MAIN EXECUTION ===

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
