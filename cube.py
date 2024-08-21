import sys
import ast


from cube import TemplateContext
template = TemplateContext()

from cube import config
import requests 
import boto3import jwt

import base64
import hashlib
import os
import urllib.parse
import redis
import json
from datetime import datetime, timedelta





OKTA_DOMAIN = os.environ["OKTA_DOMAIN"]
OKTA_CLIENT_ID = os.environ["OKTA_CLIENT_ID"]
OKTA_CLIENT_SECRET = os.environ["OKTA_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]


def get_account_id_for_principal():
    # Create an STS client
    sts_client = boto3.client('sts')

    # Get the caller identity
    response = sts_client.get_caller_identity()

    # Extract the account ID and ARN
    account_id = response['Account']

    return account_id

AWS_ACCOUNT_ID = get_account_id_for_principal()
AWS_REGION = 'us-west-2'





config.scheduled_refresh_timer = 3600

redis_client = redis.StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
CACHE_TTL = 3800


@config('logger')
def logger(message: str, params: dict) -> None:
  print(f"{message}: {params}")

def are_credentials_expired(credentials):
    """Check if the credentials are expired."""
    exp_d=credentials['Expiration']
    expiration = datetime.fromisoformat(exp_d)  # Parse the ISO 8601 format
    return datetime.now(datetime.utcnow().astimezone().tzinfo) >= expiration


def get_aws_credentials(okta_group,aws_role):
    sts_client = boto3.client('sts',verify=False)
    role_arn = aws_role
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"session-{okta_group}"
        )
    except Exception as e:
        print(f"credential retrieval failed: {e}")
    credentials = response['Credentials']

    return {
        'access_key_id': credentials['AccessKeyId'],
        'secret_access_key': credentials['SecretAccessKey'],
        'session_token': credentials['SessionToken'],
        'expiration': credentials['Expiration']
    }

def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

def authenticate_okta_user(user, password):
    
    try:
      cached_credentials = redis_client.get(f"{user}-okta")
      if cached_credentials:
          print(f"okta credentials are chached {cached_credentials} type: {type(cached_credentials)}")
          credentials=ast.literal_eval(cached_credentials)
          print("reusing okta credentials")
          return credentials
    except Exception as e:
       print(f"error fetching okta redis credentials: {e}")
    session = requests.Session()
    
    # Step 1: Authenticate user with Okta
    authn_url = f"{OKTA_DOMAIN}/api/v1/authn"
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    authn_data = {
        "username": user,
        "password": password
    }
    #response = session.post(authn_url, json=authn_data,headers=headers)
    try:
      response = session.post(authn_url, json=authn_data,headers=headers,verify=False)
      print("response went through")
      response.raise_for_status()
      logging.info(f"Response Status Code: {response.status_code}")
      logging.info(f"Response Body: {response.text}")
    except requests.exceptions.HTTPError as http_err:
      logging.error(f"HTTP error occurred: {http_err}")  # Logs specific HTTP errors
    except Exception as err:
        logging.error(f"Other error occurred: {err}")  # Logs any other errors

    session_token = response.json().get('sessionToken')
    if not session_token:
        raise ValueError("Failed to obtain session token from Okta authentication response")
    
    # Step 2: Generate PKCE code verifier and challenge
    code_verifier, code_challenge = generate_pkce_pair()
    
    # Step 3: Obtain an authorization code from Okta
    auth_url = f"{OKTA_DOMAIN}/oauth2/v1/authorize"
    auth_params = {
        "response_type": "code",
        "client_id": OKTA_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid groups",
        "state": "state-123",
        "sessionToken": session_token,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    response = session.get(auth_url, params=auth_params, allow_redirects=False,verify=False)
    if response.status_code != 302:
        print(f"Failed to obtain authorization code: {response.status_code} {response.text}")
        return None, None
    
    parsed_url = urllib.parse.urlparse(response.headers['Location'])
    auth_code = urllib.parse.parse_qs(parsed_url.query).get('code', [None])[0]
    if not auth_code:
        print("Failed to parse authorization code from redirect URL")
        return None, None
    
    # Step 4: Exchange the authorization code for an ID token and access token
    token_url = f"{OKTA_DOMAIN}/oauth2/v1/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "client_id": OKTA_CLIENT_ID,
        "client_secret": OKTA_CLIENT_SECRET,
        "code_verifier": code_verifier
    }
    
    response = session.post(token_url, data=token_data,verify=False)
    response.raise_for_status()
    
    tokens = response.json()
    id_token = tokens.get('id_token')
    access_token = tokens.get('access_token')
    credentials = {"id_token":id_token, "access_token":access_token}
    redis_client.setex(f"{user}-okta",CACHE_TTL,json.dumps(credentials))
    
    return credentials

def fetch_okta_user_groups(id_token):
    try:
        # Decode the ID token
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        
        # Extract groups from the token
        groups = decoded_token.get('groups', [])
        
        if not groups:
            logging.info("No groups found in ID token.")
            return []

        return groups

    except jwt.ExpiredSignatureError:
        logging.error("The token has expired.")
        return None
    except jwt.InvalidTokenError:
        logging.error("Invalid token.")
        return None

    
def check_iam_role_policy(role_arn, user_groups):
    client = boto3.client('iam', region_name=AWS_REGION, verify=False)
    
    role_name = role_arn.split('/')[-1]
    response = client.get_role(RoleName=role_name)
    trust_policy = response['Role']['AssumeRolePolicyDocument']
    
    # Check if any of the user groups are allowed to assume the role
    for statement in trust_policy.get('Statement', []):
        if statement['Effect'] == 'Allow' and 'Federated' in statement['Principal']:
            conditions = statement.get('Condition', {}).get('StringLike', {})
            if 'SAML:sub' in conditions:
                for group in user_groups:
                    if f"Okta:group:{group}" in conditions['SAML:sub']:
                        return True
    return False

def assume_role_with_web_identity(id_token,role_arn,okta_user):
    try:
      cached_credentials = redis_client.get(f"{okta_user}-aws")
      if cached_credentials:
          credentials= ast.literal_eval(cached_credentials)
          if not are_credentials_expired(credentials):
            print("credentials are valid")
            return credentials
    except Exception as e:
       print(f"error fetching redis credentials: {e}")

    client = boto3.client('sts', region_name=AWS_REGION,verify=False)

    
    try:
      response = client.assume_role_with_web_identity(
          RoleArn=role_arn,
          RoleSessionName="Cube-test",
          WebIdentityToken=id_token
      )
    except Exception as e:
        print(f"error with credentials {e}")

    credentials = response['Credentials']
    credentials["Expiration"] = str(credentials["Expiration"])
    try:
      redis_client.setex(f"{okta_user}-aws",CACHE_TTL,json.dumps(credentials))
    except Exception as e:
       print(f"error persisiting credentials on redis: {e}")


    return credentials




@config('driver_factory')
def driver_factory(ctx: dict) -> None:
    if ctx['securityContext'] and ctx['securityContext'].get('okta_group'):
        if ctx['securityContext'].get('access_key_id'):
                credentials = {
                    "access_key_id":ctx['securityContext']["access_key_id"],
                    "secret_access_key":ctx['securityContext']["secret_access_key"],
                    "session_token":ctx['securityContext']["aws_token"]
                }
        
                access_key = credentials['access_key_id']
                secret_key = credentials['secret_access_key']
                session_token = credentials['session_token']

                return {
                    'type': 'athena',
                    'region': os.environ["CUBEJS_AWS_REGION"],
                    "credentials": {
                        'accessKeyId': access_key,
                        "secretAccessKey": secret_key,
                        "sessionToken": session_token,
                    },
                    "S3OutputLocation": os.environ["CUBEJS_AWS_S3_OUTPUT_LOCATION"],
                    "exportBucket": os.environ["CUBEJS_DB_EXPORT_BUCKET"]
                }
    else:
       return {
        'type': 'athena',
        'region': os.environ["CUBEJS_AWS_REGION"],
        "credentials": {
        'accessKeyId': os.environ["AWS_ACCESS_KEY_ID"],
        "secretAccessKey": os.environ["AWS_SECRET_ACCESS_KEY"]#,
        #"sessionToken": os.environ["AWS_SESSION_TOKEN"]
        },
        "S3OutputLocation": os.environ["CUBEJS_AWS_S3_OUTPUT_LOCATION"],
        "exportBucket": os.environ["CUBEJS_DB_EXPORT_BUCKET"]
        }
    
@config('scheduled_refresh_contexts')
def scheduled_refresh_contexts() -> list[object]:
  print("scheduled_refresh_contexts triggered")
  aws_role = os.envion["SAMPLE_AWS_ROLE_WITH_OIDC"]
  credentials = get_aws_credentials("test_group_scheduled",aws_role)
  access_key_id = credentials['access_key_id']
  secret_access_key = credentials['secret_access_key']
  session_token = credentials['session_token']
  expiration = credentials['expiration']

  default = {
     "securityContext": {
        
     }
  }
  
  okta_group_sc = {
     "securityContext": {
        'tenant_id': "test_group",
        "okta_group":"test_group",
        "aws_role_arn": aws_role,
        "access_key_id": access_key_id ,
        "secret_access_key": secret_access_key,
        "aws_token":session_token ,
        "exp_d": str(expiration)
     }
  }

  print('schedule refresh contexts')

  return [
   okta_group_sc,
   default
  ]

@config('context_to_app_id')
def context_to_app_id(ctx: dict) -> str:
  if ctx['securityContext'] and ctx['securityContext'].get('okta_group'):
     return ctx['securityContext'].get('okta_group')
  else:
     return "CUBE_APP_DEFAULT"

 
@config('context_to_orchestrator_id')
def context_to_orchestrator_id(ctx: dict) -> str:
  if ctx['securityContext'] and ctx['securityContext'].get('okta_group'):
     return ctx['securityContext'].get('okta_group')
  else:
     return "CUBE_APP_DEFAULT"

@config('pre_aggregations_schema')
def pre_aggregations_schema(ctx: dict) -> str:
  print(f"choose preagg schema: {ctx}")
  if ctx['securityContext'] and ctx['securityContext'].get('okta_group'):
     print("okta agg schema defined")
     return ctx['securityContext'].get('okta_group')
  else:
    print("default agg schema defined")
    return f"CUBE_APP_DEFAULT"



@config('check_sql_auth')
def check_sql_auth(req: dict, user_name: str, password: str) -> dict:
  authenticated = False
  user     = user_name.split("/")[0]
  aws_role = user_name.split("/")[1]
  role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{aws_role}"
  okta_credentials = authenticate_okta_user(user,password)
  id_token = okta_credentials["id_token"]
  credentials = assume_role_with_web_identity(id_token,role_arn,user)
  

  if credentials:
      access_key_id = credentials['AccessKeyId']
      secret_access_key = credentials['SecretAccessKey']
      session_token = credentials['SessionToken']
      return {
          "password": password,
          'securityContext': {
            "okta_group":"test_group",
            "tenant_id": "test_group",
            "aws_role_arn": role_arn ,
            "access_key_id": access_key_id ,
            "secret_access_key": secret_access_key,
            "aws_token":session_token 
          }
        }
        
      
