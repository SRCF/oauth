from flask import Flask, render_template, redirect, request, url_for
import json
import requests
import pwd
from typing import List, Union, Optional, Tuple, Any
from srcf.database import queries
from .scopes import SCOPES_DATA, AUTOMATIC_SCOPES
from .utils import setup_app, auth
from hydra_session import session
from werkzeug.wrappers.response import Response
from werkzeug.exceptions import HTTPException, Unauthorized

REQUESTS_PATH = "/oauth2/auth/requests/"
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
    response = make_request(session.put, flow + "/" + action, params=challenge_obj, json=body)

    return response["redirect_to"]

def get(flow, challenge) -> dict:
    challenge_obj = {
        flow + "_challenge": challenge,
    }
    return make_request(session.get, flow, params=challenge_obj)

@app.route('/login')
def login():
    challenge = request.args["login_challenge"]
    response = get("login", challenge)

    if not response["skip"]:
        try:
            a = auth.before_request()
        except Unauthorized:
            body = {
                "error": "access_denied",
                "error_description": "User cancelled login",
            }
            return redirect(put("login", "reject", challenge, body))

        if a is not None:
            return a

        crsid = auth.principal
    else:
        crsid = response["subject"]

    body = {
        "subject": crsid,
        "remember": False,
    }

    return redirect(put("login", "accept", challenge, body))

def gen_id_token(crsid: str, scopes: List[str]) -> Tuple[List[str], dict]:
    if "openid" not in scopes:
        return ([], {})

    id_token = {}
    scopes = [x for x in scopes if x in SCOPES_DATA]

    if len(scopes) > 0:
        try:
            data = queries.get_member(crsid)
        except KeyError:
            data = requests.get(LOOKUP_PATH % crsid, headers = { "Accept": "application/json" }).json()["result"]["person"]

        for scope in scopes:
            get_claim = SCOPES_DATA[scope]["get_claims"] # type: Any
            for key, val in get_claim(crsid, data).items():
                id_token[key] = val

    return (scopes, id_token)

@app.route('/consent', methods=["GET", "POST"])
def consent():
    challenge = request.args["consent_challenge"]
    response = get("consent", challenge)

    crsid = response["subject"]
    requested_scopes = response["requested_scope"]
    audience = response["requested_access_token_audience"]

    if (
        # Hydra says that user has already consented to the scopes:
        response["skip"] or
        # Hydra feature, client is trusted and user consent is assumed:
        response["client"]["skip_consent"] or
        # SRCF specific, client is 'internal'
        # (an older way of expressing skip_consent before Hydra supported it):
        response["client"]["metadata"].get("internal", False)
    ):
        scopes, id_token = gen_id_token(crsid, requested_scopes)
    else:
        if request.method == "GET":
            scopes, id_token = gen_id_token(crsid, requested_scopes)

            data = {
                "scopes": scopes,
                "id_token": id_token,
                "SCOPES_DATA": SCOPES_DATA
            }
            return render_template('consent.html', client=response["client"], crsid=crsid, **data)
        else:
            action = request.form.get('action')

            if action == "cancel":
                body = {
                    "error": "access_denied",
                    "error_description": "User did not consent",
                }
                return redirect(put("consent", "reject", challenge, body))

            elif "openid" in requested_scopes:
                granted_scopes = request.form.getlist("scope") + ["openid"]
                granted_scopes = [x for x in granted_scopes if x in requested_scopes]
                scopes, id_token = gen_id_token(crsid, granted_scopes)
            else:
                scopes, id_token = [], {}

    scopes = scopes + [x for x in requested_scopes if x in AUTOMATIC_SCOPES]

    body = {
        "grant_scope": scopes,
        "grant_access_token_audience": audience,
        "remember": True,
        "remember_for": 60 * 60 * 24 * 30,
    }
    if "openid" in scopes:
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
