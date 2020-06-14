from flask import Flask, render_template, redirect, request, url_for
import json
import requests
import pwd
from typing import List, Union, Optional
from srcf.database import queries
from .scopes import SCOPES_DATA
from .utils import setup_app, auth
from werkzeug.wrappers.response import Response
from werkzeug.exceptions import HTTPException

REQUESTS_PATH = "http://localhost:4445/oauth2/auth/requests/"
JSON_HEADER = { "Content-Type": "application/json" }
FAKE_TLS_HEADER = { "X-Forwarded-Proto": "https" }
LOOKUP_PATH = "https://www.lookup.cam.ac.uk/api/v1/person/crsid/%s?fetch=email,departingEmail"

app = Flask(__name__, template_folder="templates")
setup_app(app)

class APIError(Exception):
    def __init__(self, msg: str):
        self.msg = msg

def make_request(fun, endpoint: str, **kwargs) -> dict:
    path = REQUESTS_PATH + endpoint
    try:
        response = fun(path, **kwargs)
    except requests.exceptions.ConnectionError as e:
        raise APIError(f"Failed to connect to Hydra Admin API endpoint /{endpoint}: {e}")

    if response.status_code != 200:
        raise APIError(f"Error returned by Hydra Admin API endpoint /{endpoint}: {response.text}")

    try:
        return response.json()
    except ValueError:
        raise APIError(f"Invalid JSON received from Hydra Admin API endpoint /{endpoint}: '{response.text}'")

def put(flow: str, action: str, challenge: str, body: dict) -> str:
    challenge_obj = {
        flow + "_challenge": challenge,
    }
    response = make_request(requests.put, flow + "/" + action, params=challenge_obj, headers={**JSON_HEADER, **FAKE_TLS_HEADER}, data=json.dumps(body))

    return response["redirect_to"]

def get(flow, challenge) -> dict:
    challenge_obj = {
        flow + "_challenge": challenge,
    }
    return make_request(requests.get, flow, headers=FAKE_TLS_HEADER, params=challenge_obj)

@app.route('/login')
def login():
    challenge = request.args["login_challenge"]
    response = get("login", challenge)

    if response["skip"]:
        return complete_login(response["subject"], challenge)
    else:
        return redirect(url_for("login_check", challenge=challenge))

def complete_login(crsid: str, challenge: str):
    body = {
        "subject": crsid,
        "remember": True,
        "remember_for": 3600,
    }

    return redirect(put("login", "accept", challenge, body))

@app.route('/login_check/<challenge>')
@auth
def login_check(challenge: str):
    return complete_login(auth.principal, challenge)

def read_filter_scopes(crsid: str, scopes: List[str], openid: bool=True) -> (List[str], Optional[dict]):
    if "openid" not in scopes:
        return ([], None)

    id_token = {}
    scopes = [x for x in scopes if x in SCOPES_DATA]

    if len(scopes) > 0:
        try:
            data = queries.get_member(crsid)
        except KeyError:
            data = requests.get(LOOKUP_PATH % crsid, headers = { "Accept": "application/json" }).json()["result"]["person"]

        for scope in scopes:
            for key, val in SCOPES_DATA[scope]["get_claims"](crsid, data).items():
                id_token[key] = val

    if openid:
        scopes.append("openid")

    return (scopes, id_token)

@app.route('/consent', methods=["GET", "POST"])
def consent():
    challenge = request.args["consent_challenge"]
    response = get("consent", challenge)

    crsid = response["subject"]
    requested_scopes = response["requested_scope"]
    audience = response["requested_access_token_audience"]

    if response["skip"]:
        scopes, id_token = read_filter_scopes(crsid, requested_scopes)

        body = {
            "grant_scope": scopes,
            "grant_access_token_audience": audience,
            "remember": True,
            "remember_for": 3600,
        }
        if id_token is not None:
            body["session"] = {
                "id_token": id_token
            }

        return redirect(put("consent", "accept", challenge, body))

    if request.method == "GET":
        scopes, id_token = read_filter_scopes(crsid, requested_scopes, openid=False)

        data = {
            "scopes": scopes,
            "id_token": id_token,
            "SCOPES_DATA": SCOPES_DATA
        }
        return render_template('consent.html', client=response["client"], **data)

    action = request.form.get('action')

    if action == "cancel":
        body = {
            "error": "consent_rejected",
            "error_description": "User did not consent",
        }
        return redirect(put("consent", "reject", challenge, body))

    else:
        granted_scopes = request.form.getlist("scope") + ["openid"]
        granted_scopes = [x for x in granted_scopes if x in requested_scopes]
        scopes, id_token = read_filter_scopes(crsid, granted_scopes)

        body = {
            "grant_scope": scopes,
            "grant_access_token_audience": audience,
            "remember": True,
            "remember_for": 3600,
        }
        if id_token is not None:
            body["session"] = {
                "id_token": id_token
            }

        return redirect(put("consent", "accept", challenge, body))

@app.route('/error')
def error():
    return render_template('error.html', **request.args)

@app.errorhandler(APIError)
def handle_internal_exception(e):
    return redirect(url_for("error", status_code=500, error="Internal Server Error", error_description=e.msg))

@app.errorhandler(HTTPException)
def handle_exception(e):
    return render_template('error.html', status_code=e.code, error=e.name, error_description=e.description)
