from typing import Union
from srcf.database import Member

# data is a Member object if crsid belongs to an SRCF member, and the lookup
# data otherwise.
def get_name(crsid: str, data: Union[Member, dict]) -> dict:
    if isinstance(data, Member):
        return {
            "name": data.name,
            "family_name": data.surname,
            "given_name": data.preferred_name,
            "preferred_username": crsid,
            "username": crsid,
        }
    else:
        return {
            "name": data["visibleName"],
            "family_name": data["surname"],
            "preferred_username": crsid,
            "username": crsid,
        }

def get_groups(crsid: str, data: Union[Member, dict]) -> dict:
    if isinstance(data, Member):
        return {
            "groups": [x.name for x in data.societies]
        }
    else:
        return { "groups": [] }

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
        "get_claims": get_name,
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
