# Importing LangChain libraries
from langchain.agents import AgentExecutor, load_tools, initialize_agent, tool
from langchain.schema import SystemMessage
from langchain.agents import OpenAIFunctionsAgent, AgentType
from langchain.chat_models import ChatOpenAI
from langchain import LLMMathChain, SerpAPIWrapper
from langchain.tools import BaseTool, StructuredTool, Tool
from dotenv import load_dotenv, find_dotenv

# Importing standard libraries for Google My Business
import os
import logging
import secrets
import datetime

# Importing third-party libraries for Google My Business
import flask
import requests
import redis
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from flask_cors import CORS
from flask import Flask, request, session
from flask_session import Session

# account for deprecation of LLM model
import datetime
# Get the current date
current_date = datetime.datetime.now().date()

# Define the date after which the model should be set to "gpt-3.5-turbo"
target_date = datetime.date(2024, 6, 12)

# Set the model variable based on the current date
if current_date > target_date:
    llm_model = "gpt-3.5-turbo"
else:
    llm_model = "gpt-3.5-turbo-0301"
    
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
CORS(app)
   
# Tool
llm = ChatOpenAI(temperature=0)
tools = load_tools(["serpapi", "llm-math"], llm=llm)

# Utility to convert Google OAuth2 credentials to a dictionary
def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# Utility to generate random string
def generate_random_string(length):
    return secrets.token_hex(length)

# Custom Tool to fetch reviews
@tool
def fetch_reviews_tool(location_name: str):
    # Logic to fetch reviews from Google My Business
    return f"Fetched reviews for {location_name}"

# Initialize LangChain Agent
llm = ChatOpenAI(temperature=0)
tools = load_tools(["serpapi", "llm-math"], llm=llm)

agent = initialize_agent(
    tools + [fetch_reviews_tool], 
    llm, 
    agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    handle_parsing_errors=True,
    verbose=True
)

# Flask route to fetch reviews
@app.route('/fetch_reviews', methods=['GET'])
def fetch_reviews():
    location_name = request.args.get('location_name')
    if location_name:
        reviews = fetch_reviews_tool(location_name)
        return flask.jsonify({"reviews": reviews})
    else:
        return flask.jsonify({"error": "Invalid location name"}), 400

# Main Execution
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
