from flask import Flask, render_template, redirect, request, url_for
import json
import requests
import pwd
from typing import List, Union
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

class InternalError(Exception):
    def __init__(self, error: dict):
        self.error = error

    def display(self) -> Response:
        return redirect(url_for("error", **self.error))

    @staticmethod
    def json_error(data: str) -> 'InternalError':
        return InternalError({
            "status_code": 500,
            "error": "Internal Server Error",
            "error_description": "Invalid JSON received from Hydra Admin API: '{}'".format(data),
        })

    @staticmethod
    def connection_error() -> 'InternalError':
        return InternalError({
            "status_code": 500,
            "error": "Internal Server Error",
            "error_description": "Failed to connect to Hydra Admin API",
        })

    @staticmethod
    def api_error(endpoint: str, error: str) -> 'InternalError':
        return InternalError({
            "status_code": 500,
            "error": "Internal Server Error",
            "error_description": "Error when accessing api endpoint /{}: {}".format(endpoint, error),
        })

def make_request(fun, endpoint: str, **kwargs) -> dict:
    path = REQUESTS_PATH + endpoint
    try:
        response = fun(path, **kwargs)
    except ConnectionError:
        raise InternalError.connection_error()

    if response.status_code != requests.codes.ok:
        raise InternalError.api_error(endpoint, response.text)

    try:
        response_json = response.json()
    except ValueError:
        raise InternalError.json_error(response.text)

    return response_json

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
    try:
        response = get("login", challenge)
    except InternalError as e:
        return e.display()

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

    try:
        return redirect(put("login", "accept", challenge, body))
    except InternalError as e:
        return e.display()

@app.route('/login_check/<challenge>')
@auth
def login_check(challenge: str):
    return complete_login(auth.principal, challenge)

def read_filter_scopes(crsid: str, scopes: List[str], openid: bool=True) -> (List[str], dict):
    id_token = {}

    # We can only grant scopes that are in SCOPES_DATA, apart from openid. We
    # remember if openid is present and add it back at the end.
    add_openid = openid and "openid" in scopes # type: bool
    scopes = [x for x in scopes if x in SCOPES_DATA]

    if len(scopes) > 0:
        try:
            data = queries.get_member(crsid)
        except KeyError:
            data = requests.get(LOOKUP_PATH % crsid, headers = { "Accept": "application/json" }).json()["result"]["person"]

    for scope in scopes:
        for key, val in SCOPES_DATA[scope]["get_claims"](crsid, data).items():
            id_token[key] = val

    if add_openid:
        scopes.append("openid")

    return (scopes, id_token)

@app.route('/consent', methods=["GET", "POST"])
def consent():
    challenge = request.args["consent_challenge"]
    try:
        response = get("consent", challenge)
    except InternalError as e:
        return e.display()

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
            "session": {
                "id_token": id_token
            }
        }

        try:
            return redirect(put("consent", "accept", challenge, body))
        except InternalError as e:
            return e.display()

    if request.method == "GET":
        scopes, id_token = read_filter_scopes(crsid, requested_scopes, openid=False)

        data = {
            "scopes": scopes,
            "id_token": id_token,
            "SCOPES_DATA": SCOPES_DATA
        }
        return render_template('authorize.html', client=response["client"], **data)

    action = request.form.get('action')

    if action == "cancel":
        body = {
            "error": "consent_rejected",
            "error_description": "User did not consent",
        }
        try:
            return redirect(put("consent", "reject", challenge, body))
        except InternalError as e:
            return e.display()

    else:
        granted_scopes = request.form.getlist("scope") + ["openid"]
        granted_scopes = [x for x in granted_scopes if x in requested_scopes]
        scopes, id_token = read_filter_scopes(crsid, granted_scopes)

        body = {
            "grant_scope": scopes,
            "grant_access_token_audience": audience,
            "remember": True,
            "remember_for": 3600,
            "session": {
                "id_token": id_token
            }
        }

        try:
            return redirect(put("consent", "accept", challenge, body))
        except InternalError as e:
            return e.display()

@app.route('/error')
def error():
    return render_template('error.html', **request.args)

@app.errorhandler(HTTPException)
def handle_exception(e):
    return InternalError({
            "status_code": e.code,
            "error": e.name,
            "error_description": e.description,
        }).display()
