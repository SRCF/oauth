from typing import Union
from srcf.database import Member

# Convert a crsid to a numerical string
def get_id(crsid: str):
    id_ = 0
    power = 1
    is_num = False
    for c in list(crsid):
        if not is_num:
            n = ord(c) - ord('a')
            if 0 <= n < 26:
                id_ += n * power
            else:
                is_num = True
                id_ += 26 * power
                power *= 27

        if is_num:
            id_ += (ord(c) - ord('0')) * power

        power *= 27

    return id_

# data is a Member object if crsid belongs to an SRCF member, and the lookup
# data otherwise.
def get_profile(crsid: str, data: Union[Member, dict]) -> dict:
    if isinstance(data, Member):
        return {
            "name": data.name,
            "family_name": data.surname,
            "given_name": data.preferred_name,
            "preferred_username": crsid,
            "username": crsid,
            "login": crsid,
            "id": get_id(crsid),
        }
    else:
        return {
            "name": data["visibleName"],
            "family_name": data["surname"],
            "preferred_username": crsid,
            "username": crsid,
            "login": crsid,
            "id": get_id(crsid),
        }

def get_groups(crsid: str, data: Union[Member, dict]) -> dict:
    if isinstance(data, Member):
        return {
            "groups": [x.society for x in data.societies],
            "groups_details": {x.society:x.description for x in data.societies}
        }
    else:
        return { "groups": [], "groups_details": {} }

def get_email(crsid: str, data: Union[Member, dict]) -> dict:
    if isinstance(data, Member):
        return {
            "email": crsid + "@srcf.net",
            "email_verified": True,
        }
    else:
        for entry in data["attributes"]:
            if entry["scheme"] == "email" or entry["scheme"] == "departingEmail":
                return { "email": entry["value"] }

        return {}

SCOPES_DATA = {
    "profile": {
        "description": "Name",
        "get_claims": get_profile,
        "value_str": lambda x: x["name"],
    },
    "email": {
        "description": "Email",
        "get_claims": get_email,
        "value_str": lambda x: x["email"],
    },
    "groups": {
        "description": "SRCF societies membership",
        "get_claims": get_groups,
        "value_str": lambda x: ""
    },
}

AUTOMATIC_SCOPES = {"openid", "offline", "offline_access" }
