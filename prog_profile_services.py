from functools import wraps
import json
from os import environ as env
from typing import Dict
import time
from six.moves.urllib.request import urlopen

from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, jsonify, _request_ctx_stack, Response, render_template
from flask_cors import cross_origin
from jose import jwt


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
SECRET = env.get("SECRET")

def validate_session_token_from_request(session_token):
  # secret = os.environ.get('SECRET')
  result = {
    "data": {
      "page_style" : "basic_landing",
      "page_title" : "🚨 Session Invalid!",
      "page_content": "Please Try Again!"
    }
  }
  # example_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NTcwNjc0ODIsImlzcyI6Imh0dHBzOi8vcHJvZy1wcm9maWxlLWV4YW1wbGUudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDYyYzRiMmVkY2U2NDZiNWExOTAwY2ZkZCIsImV4cCI6MTY1NzA2ODM4MiwiaXAiOiIyNjA0OjNkMDg6OGM3ZTplNTAwOjFjN2E6MWFkNDo0NmZhOmVhMDgiLCJzdWJqZWN0IjoiYXV0aDB8NjJjNGIyZWRjZTY0NmI1YTE5MDBjZmRkIiwiYXVkaWVuY2UiOiJodHRwczovL3Byb3Byb2ZpbGUtZGVtby5nbGl0Y2gubWUvcHJvZy9nZW5lcmFsIiwiZXhwaXJlc0luIjoiNSBtaW51dGVzIiwiZGF0YSI6eyJwYWdlX3N0eWxlIjoiYmFzaWNfZm9ybSIsInBhZ2VfdGl0bGUiOiJQcm9ncmVzc2l2ZSBQcm9maWxpbmcgRm9ybSIsInBhZ2VfY29udGVudCI6W3sidGV4dCI6IkZpcnN0IE5hbWUiLCJyZXNwb25zZV90eXBlIjoidGV4dCIsIm1ldGFkYXRhX2tleSI6ImZpcnN0X25hbWUifSx7InRleHQiOiJFbnRlciBBZ2UiLCJyZXNwb25zZV90eXBlIjoidGV4dCIsIm1ldGFkYXRhX2tleSI6ImFnZSJ9XX19.dyEgnZAs78uZPh-61yN9xiVb0tIhL6GchF-6GtiCgZo"
  # session_token = example_token
  try:
    result = jwt.decode(session_token, SECRET, algorithms=["HS256"])
    # print(result)
  except jwt.ExpiredSignatureError:
    print("expired_token")
    result["data"]["page_content"] = "Expired Session Token. Please Try Again!"
  except jwt.InvalidTokenError:
    print("invalid_token")
    result["data"]["page_content"] = "Invalid Session Token. Please Try Again!"
  return result
    
  
def get_content_formatting(session_token_data):
  if session_token_data["page_style"] == "basic_form":
    # example_content = {"page_content": [{"text": "How are you","response_type": "text","metadata_key": "mood"},{"text": "Enter Age","response_type": "text","metadata_key": "age"}]}
    # session_token_data = example_content
    # print("basic form to be rendered")
    # print(session_token_data["page_content"])
    for each_form_item in session_token_data["page_content"]:
      continue
      # print(each_form_item["text"])
  return session_token_data["page_content"]
  
  
def redirect_continue_url(session_token, state, redirect_uri):
  url = f'{redirect_uri}?state={state}&session_token={session_token}'
  print(f"final_state: {state}")
  print(url)
  return url


def get_endcoded_session_token(additonal_data, state, original_session_token=None):
  payload = {}
  if original_session_token is not None:
    payload = validate_session_token_from_request(original_session_token)
  # print(int(time.time()))
  payload["iat"] = int(time.time())
  payload["state"] = state
  payload["exp"] = int(time.time()) + (5*600)
  payload["other"] = additonal_data
  # print(payload)
  encoded = jwt.encode(payload, SECRET, algorithm="HS256")
  return encoded