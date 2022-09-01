"""Python Flask API Auth0 integration example
"""

# return render_template('basic_landing.html',
#                            title="🏠 Home Page",
#                            content="This is the homepage for this heroku test server.",
#                            url_link=None,
#                            button_action=None,
#                            button_text=None,
#                            action_type=None
#                            )
#

from functools import wraps
import json
from os import environ as env
from typing import Dict

from six.moves.urllib.request import urlopen
from urllib.parse import urlencode
import requests
from bs4 import BeautifulSoup
import re

from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, jsonify, _request_ctx_stack, Response, render_template, session, redirect, url_for
from flask_session import Session
from flask_cors import cross_origin
from jose import jwt
from prog_profile_services import validate_session_token_from_request, get_content_formatting, redirect_continue_url, get_endcoded_session_token

# ENV_FILE = find_dotenv()
# if ENV_FILE:
#     load_dotenv(ENV_FILE)
# AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
# API_IDENTIFIER = env.get("API_IDENTIFIER")
ALGORITHMS = ["RS256"]
APP = Flask(__name__, static_folder='styles',)
APP.config["SESSION_PERMANENT"] = False
APP.config["SESSION_TYPE"] = "filesystem"
Session(APP)



# Format error response and append status code.
class AuthError(Exception):
    """
    An AuthError is raised whenever the authentication failed.
    """
    def __init__(self, error: Dict[str, str], status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


@APP.errorhandler(AuthError)
def handle_auth_error(ex: AuthError) -> Response:
    """
    serializes the given AuthError as json and sets the response status code accordingly.
    :param ex: an auth error
    :return: json serialized ex response
    """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def get_token_auth_header() -> str:
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                             "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    if len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    if len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must be"
                             " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_scope(required_scope: str) -> bool:
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False


def requires_auth(func):
    """Determines if the access token is valid
    """
    
    @wraps(func)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError as jwt_error:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401) from jwt_error
        if unverified_header["alg"] == "HS256":
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Invalid header. "
                                 "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except jwt.ExpiredSignatureError as expired_sign_error:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401) from expired_sign_error
            except jwt.JWTClaimsError as jwt_claims_error:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"}, 401) from jwt_claims_error
            except Exception as exc:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401) from exc

            _request_ctx_stack.top.current_user = payload
            return func(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)

    return decorated
  

@APP.route('/')
def home():
  session["counter"]=0
  print("Counter Reset")
  return render_template('basic_link_list.html',
                           title="🏠 Home Page",
                           content="This is the homepage for this test server.",
                           url_links=["https://awhitdem0-be.herokuapp.com/api/supportdesk"],
                           button_texts=["📲 Push Verify Support Desk"]
                           )
    
  
    
@APP.route('/prog/generic')
def progressive_prop():
#   Clear existing session values
  session_token = request.args.get('session_token')
  redirect = request.args.get('redirect_uri')
  state = request.args.get('state')
  print(f"starting_state: {state}")
  session["session_token"]=session_token
  session["redirect"]=redirect
  session["state"]=state
  # example_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NTcwOTE4NjEsImlzcyI6Imh0dHBzOi8vcHJvZy1wcm9maWxlLWV4YW1wbGUudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDYyYzRiMmVkY2U2NDZiNWExOTAwY2ZkZCIsImV4cCI6MTY1NzA5Mjc2MSwiaXAiOiIyNjA0OjNkMDg6OGM3ZTplNTAwOjFjN2E6MWFkNDo0NmZhOmVhMDgiLCJzdWJqZWN0IjoiYXV0aDB8NjJjNGIyZWRjZTY0NmI1YTE5MDBjZmRkIiwiYXVkaWVuY2UiOiJodHRwczovL3Byb3Byb2ZpbGUtZGVtby5nbGl0Y2gubWUvcHJvZy9nZW5lcmFsIiwiZXhwaXJlc0luIjoiNSBtaW51dGVzIiwiZGF0YSI6eyJwYWdlX3N0eWxlIjoiYmFzaWNfZm9ybSIsInBhZ2VfdGl0bGUiOiJQcm9ncmVzc2l2ZSBQcm9maWxpbmcgRm9ybSIsInBhZ2VfY29udGVudCI6W3sidGV4dCI6IkZpcnN0IE5hbWUiLCJyZXNwb25zZV90eXBlIjoidGV4dCIsIm1ldGFkYXRhX2tleSI6ImZpcnN0X25hbWUifSx7InRleHQiOiJFbnRlciBBZ2UiLCJyZXNwb25zZV90eXBlIjoidGV4dCIsIm1ldGFkYXRhX2tleSI6ImFnZSJ9LHsidGV4dCI6IkVudGVyIExhc3QgTmFtZSIsInJlc3BvbnNlX3R5cGUiOiJ0ZXh0IiwibWV0YWRhdGFfa2V5IjoibGFzdF9uYW1lIn1dfX0.-mAaX0royydE5hLI--dUC7ii6WAAMr75nBacI184uig"
  # session_token = example_token
  if session_token is not None:
    valid_session_token = validate_session_token_from_request(session_token)
    # contents = session_token.get("contents", False)
    page_contents = valid_session_token.get("data")
    formatted_content = get_content_formatting(page_contents)
    font_family = page_contents["page_branding"].get("font_family", "serif")
    # print(formatted_content)
    button_colour = page_contents["page_branding"].get("button_colour", "EEEEEE")
    return render_template(f'{page_contents["page_style"]}.html',
                             title=f'{page_contents["page_title"]}',
                             i=formatted_content,
                           action_route="/prog/general/complete",
                           style=dict(background_image=f'{page_contents["page_branding"]["background_image"]}', 
                                      font=f'{page_contents["page_branding"]["font"]}',
                                     font_family=f'{font_family}',
                                     button_colour=button_colour)
                             )
  else:
    return render_template("basic_landing.html",
                             title="No Active Auth Session Detected",
                             content="Please Try Again!",
                             )    
    
@APP.route('/prog/universal')
def progressive_universal():
#   Clear existing session values
  session_token = request.args.get('session_token')
  redirect = request.args.get('redirect_uri')
  state = request.args.get('state')
  session["session_token"]=session_token
  session["redirect"]=redirect
  session["state"]=state
  # example_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NTcwOTE4NjEsImlzcyI6Imh0dHBzOi8vcHJvZy1wcm9maWxlLWV4YW1wbGUudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDYyYzRiMmVkY2U2NDZiNWExOTAwY2ZkZCIsImV4cCI6MTY1NzA5Mjc2MSwiaXAiOiIyNjA0OjNkMDg6OGM3ZTplNTAwOjFjN2E6MWFkNDo0NmZhOmVhMDgiLCJzdWJqZWN0IjoiYXV0aDB8NjJjNGIyZWRjZTY0NmI1YTE5MDBjZmRkIiwiYXVkaWVuY2UiOiJodHRwczovL3Byb3Byb2ZpbGUtZGVtby5nbGl0Y2gubWUvcHJvZy9nZW5lcmFsIiwiZXhwaXJlc0luIjoiNSBtaW51dGVzIiwiZGF0YSI6eyJwYWdlX3N0eWxlIjoiYmFzaWNfZm9ybSIsInBhZ2VfdGl0bGUiOiJQcm9ncmVzc2l2ZSBQcm9maWxpbmcgRm9ybSIsInBhZ2VfY29udGVudCI6W3sidGV4dCI6IkZpcnN0IE5hbWUiLCJyZXNwb25zZV90eXBlIjoidGV4dCIsIm1ldGFkYXRhX2tleSI6ImZpcnN0X25hbWUifSx7InRleHQiOiJFbnRlciBBZ2UiLCJyZXNwb25zZV90eXBlIjoidGV4dCIsIm1ldGFkYXRhX2tleSI6ImFnZSJ9LHsidGV4dCI6IkVudGVyIExhc3QgTmFtZSIsInJlc3BvbnNlX3R5cGUiOiJ0ZXh0IiwibWV0YWRhdGFfa2V5IjoibGFzdF9uYW1lIn1dfX0.-mAaX0royydE5hLI--dUC7ii6WAAMr75nBacI184uig"
  # session_token = example_token
  if session_token is not None:
    valid_session_token = validate_session_token_from_request(session_token)
    # contents = session_token.get("contents", False)
    data = valid_session_token.get("data")
    event = data["event"]
    event_request = event["request"]
    query = event_request["query"]
    query_string = f'{urlencode(query, doseq=False)}'
    signin_url = f'https://{event_request["hostname"]}/authorize?{query_string}'
    print(f"getting ul_html: {signin_url}")
    ul_response = requests.get(signin_url)
    ul_html = BeautifulSoup(ul_response.text, 'html.parser')
    ul_image_element = ul_html.find('img', attrs={"id":"prompt-logo-center"})
    ul_style_element = ul_html.find('style', attrs={"id":"custom-styles-container"})
    ul_style_element_text = ul_style_element.text
    btn_background_re = re.search( r'\.ce4c446b5[\s]*\{[\s]*background-color:[\s]*#([0-9A-Fa-f]{6})', ul_style_element_text, re.M)
    btn_background_rgb = "0, 0, 0"
    if btn_background_re is not None:
      btn_background_rgb = str(tuple(int(btn_background_re.group(1)[i:i+2], 16) for i in (0, 2, 4)))[1:-1]
    else:
      primary_color_re = re.search( r'{.*\s*.*--primary-color:\s*#([0-9A-Fa-f]{6})', ul_style_element_text, re.M)
      if primary_color_re is not None:
        btn_background_rgb = str(tuple(int(primary_color_re.group(1)[i:i+2], 16) for i in (0, 2, 4)))[1:-1]
      
    print(f"Parsed RGB: {btn_background_rgb}")
    return render_template(f'new_ul.html',
                             title=f'{data["title"]}',
                             heading=f'{data["heading"]}',
                             lead=f'{data["lead"]}',
                             inputs=data["inputs"],
                             button_text=f'{data["button_text"]}',
                             custom_styles=ul_style_element_text,
                             primary_color_rgb = btn_background_rgb,
                             # logo_src=ul_image_element["src"],
                             logo_element=ul_image_element,
                             state=state,
                             action_route="/prog/general/complete")
  else:
    return render_template("new_ul.html",
                             title="No Active Auth Session Detected",
                             content="Please Try Again!",
                             )    
    
@APP.route('/prog/general/complete', methods= ['POST'])
def complete_prog():
  # url = redirect_continue_url()
  form_data = request.form.to_dict()
  # print(form_data)
  original_session_token = session["session_token"]
  redirect_uri = session["redirect"]
  state = session["state"]
  session_token = get_endcoded_session_token(form_data, state, original_session_token)
  url = redirect_continue_url(session_token, state, redirect_uri)
  # url = "https://mail.google.com/mail/u/0/#inbox"
  return redirect(url, code=307)
  
  


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=env.get("PORT", 3010))

