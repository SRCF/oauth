from flask import Flask, render_template, redirect, request, url_for, session
import os
import json
import requests
import ucam_webauth
import ucam_webauth.rsa
import ucam_webauth.flask_glue
import pwd
from werkzeug.middleware.proxy_fix import ProxyFix

HOSTNAME = os.environ["FLASK_HOSTNAME"]

REQUESTS_PATH = "https://%s:444/oauth2/auth/requests/" % HOSTNAME
JSON_HEADER = { "Content-Type": "application/json" }
GOOSE_MESSAGE = "SRCF OpenID Connect lets you identify yourself to other applications securely without sharing your credentials. After you login, you will learn more about the application seeking your information and decide how much information to share with them (if any)."

SCOPES = {
    "profile": {
        "description": "Name",
        "value_getter": lambda x: pwd.getpwnam(x).pw_gecos.rsplit(",",maxsplit=4)[0],
    },
    "email": {
        "description": "Name",
        "value_getter": lambda x: x + "@srcf.net",
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

@app.route('/consent', methods=["GET", "POST"])
def consent():
    if request.method == "GET":
        challenge = request.args["consent_challenge"]
        response = get("consent", challenge)

        session["response"] = response
        session["challenge"] = challenge

        scopes = []
        for scope in response["requested_scope"]:
            if scope not in SCOPES:
                continue

            data = SCOPES[scope]
            scopes.append({
                "name": scope,
                "description": data["description"],
                "value": data["value_getter"](response["subject"])
            })

        return render_template('authorize.html', client=response["client"], scopes=scopes)
    else:
        response = session["response"]
        challenge = session["challenge"]

        del session["response"]
        del session["challenge"]

        action = request.form.get('action')

        if action == "cancel":
            body = {
                "error": "consent_rejected",
                "error_description": "User refused to consent",
            }
            return redirect(put("consent", "reject", challenge, body))

        crsid = response["subject"]
        audience = response["requested_access_token_audience"]

        requested_scope = response["requested_scope"]
        scopes = ["openid"]
        id_token = {}
        for scope in request.form.getlist("scope"):
            if scope not in SCOPES or scopes not in requested_scope:
                continue

            scopes.append(scope)
            id_token[scope] = SCOPES[scope]["value_getter"](crsid)

        if "openid" in requested_scope:
            scopes.append("openid")

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
