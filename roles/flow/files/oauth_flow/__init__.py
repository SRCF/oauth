from flask import Flask, render_template, redirect, request, url_for
import os
import json
import requests
import ucam_webauth
import ucam_webauth.rsa
import ucam_webauth.flask_glue
import pwd
from werkzeug.middleware.proxy_fix import ProxyFix
from typing import Optional, List


HOSTNAME = os.environ["FLASK_HOSTNAME"]

REQUESTS_PATH = "https://%s:444/oauth2/auth/requests/" % HOSTNAME
JSON_HEADER = { "Content-Type": "application/json" }
GOOSE_MESSAGE = "SRCF OpenID Connect lets you identify yourself to other applications securely without sharing your credentials. After you login, you will learn more about the application seeking your information and decide how much information to share with them (if any)."
LOOKUP_PATH = "https://www.lookup.cam.ac.uk/api/v1/person/crsid/%s?fetch=email,departingEmail"

# lookup is the data returned by lookup if the crsid does not belong to an
# SRCF user, None otherwise.
def get_name(crsid: str, lookup: Optional[dict]):
    if lookup is None:
        return pwd.getpwnam(crsid).pw_gecos.rsplit(",",maxsplit=4)[0]
    else:
        return lookup["visibleName"]

def get_email(crsid: str, lookup: Optional[dict]):
    if lookup is None:
        return crsid + "@srcf.net"
    else:
        for entry in lookup["attributes"]:
            if entry["scheme"] == "email" or entry["scheme"] == "departingEmail":
                return entry["value"]

        return crsid + "@cam.ac.uk"

SCOPES_DATA = {
    "profile": {
        "description": "Name",
        "value_getter": get_name
    },
    "email": {
        "description": "Email",
        "value_getter": get_email
    }
}

class WLSRequest(ucam_webauth.Request):
    def __str__(self):
        query_string = ucam_webauth.Request.__str__(self)
        return "https://auth.srcf.net/wls/authenticate?" + query_string

class WLSResponse(ucam_webauth.Response):
    keys = dict()
    for kid in (2, 500):
        with open('/etc/ucam_webauth_keys/pubkey{}'.format(kid), 'rb') as f:
            keys[str(kid)] = ucam_webauth.rsa.load_key(f.read())

class WLSAuthDecorator(ucam_webauth.flask_glue.AuthDecorator):
    request_class = WLSRequest
    response_class = WLSResponse
    logout_url = "https://auth.srcf.net/logout"

auth = WLSAuthDecorator(desc="SRCF OpenID Connect", require_ptags=None, iact=True, msg=GOOSE_MESSAGE)

app = Flask(__name__, template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)
app.secret_key = os.environ['FLASK_SECRET_KEY']
app.request_class.trusted_hosts = [HOSTNAME]

def put(flow: str, action: str, challenge: str, body: dict) -> str:
    path = "%s%s/%s" % (REQUESTS_PATH, flow, action)
    challenge_obj = {
        flow + "_challenge": challenge,
    }
    response = requests.put(path, params=challenge_obj, headers=JSON_HEADER, data=json.dumps(body)).json()

    if "error" in response:
        raise ValueError("Error when processing {} - {}".format(path, response))

    return response["redirect_to"]

def get(flow, challenge) -> dict:
    path = REQUESTS_PATH + flow
    challenge_obj = {
        flow + "_challenge": challenge,
    }
    response = requests.get(path, params=challenge_obj).json()

    if "error" in response:
        raise ValueError("Error when processing {} - {}".format(path, response))

    return response

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
    # What if auth fail
    return complete_login(auth.principal, challenge)

def read_filter_scopes(crsid: str, requested_scopes: List[str], openid: bool=True) -> (List[str], dict):
    scopes = []
    id_token = {}
    lookup = None

    if openid and "openid" in requested_scopes:
        scopes.append("openid")

    if next((x for x in requested_scopes if x in SCOPES_DATA), None) is not None:
        try:
            pwd.getpwnam(crsid)
        except KeyError:
            lookup = requests.get(LOOKUP_PATH % crsid, headers = { "Accept": "application/json" }).json()["result"]["person"]

    for scope in requested_scopes:
        if scope not in SCOPES_DATA:
            continue

        scopes.append(scope)
        id_token[scope] = SCOPES_DATA[scope]["value_getter"](crsid, lookup)

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
            "session": {
                "id_token": id_token
            }
        }

        return redirect(put("consent", "accept", challenge, body))

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
            "session": {
                "id_token": id_token
            }
        }

        return redirect(put("consent", "accept", challenge, body))
