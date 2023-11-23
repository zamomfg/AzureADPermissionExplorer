import argparse
from array import array
import os
import json
import datetime
from prompt_toolkit import Application
import requests
from dataclasses import dataclass, field
from typing import List

# appHeader=("appId" "appDisplayName" "permissionResource" "permissionName" "permissionDescription" "permissionType" "permissionId" "appOwners" "isDangerous" "comment" "LatestPasswordExpiryDate", "LatestKeyExpiryDate")
# ownerHeader=("userPrincipalName" "permissionResource" "permissionName" "permissionDescription" "permissionType" "permissionId" "appId" "appDisplayName" "isDangerous" "comment")

@dataclass
class Permission:
    permission_resource: str
    permission_id: str
    permission_scope: str
    # permission_name: str
    # permission_description: str
    # is_iangerous: bool
    # comment: str

    def __str__(self) -> str:
        string = f"{self.permission_resource, self.permission_id, self.permission_scope}"
        return string

@dataclass
class Owner:
    upn: str
    apps: List[object] = field(default_factory=list)

    def add_app(self, app: object):
        self.apps.append(app)

    def __str__(self) -> str:
        string = f"{self.upn}"
        return string

    @staticmethod
    def get_header() -> str:
        string = "upn"
        return string

@dataclass
class Secret:
    display_name: str
    end_date: datetime.datetime

    def has_expired(self):
        return self.end_date < datetime.datetime.now()

@dataclass
class App:
    app_id: str
    obj_id: str
    display_name: str
    app_owners : List[Owner] = field(default_factory=list)
    app_permissions : List[Permission] = field(default_factory=list)
    secret_keys : List[Secret] = field(default_factory=list)
    secret_passwords : List[Secret] = field(default_factory=list)

    def add_owner(self, owner: Owner):
        self.app_owners.append(owner)

    def add_owners(self, owners: List[Owner]):
        self.app_owners += owners

    def add_permission(self, permission: Permission):
        self.app_permissions.append(permission)
    
    def add_permissions(self, permissions: List[Permission]):
        self.app_permissions += permissions

    def add_key(self, key: Secret):
        self.secret_keys.append(key)

    def add_password(self, password: Secret):
        self.secret_passwords.append(password)

    def has_active_secrets(self):
        secrets = self.secret_keys + self.secret_passwords

        if len(secrets) == 0:
            return "No secrets"

        for secret in secrets:
            if secret.has_expired() == False:
                return "Not Expired"
    
        return "Expired"
    
    def print_owners(self):
        own_list = []
        for own in self.app_owners:
            own_list.append(own.upn)

        if len(own_list) > 0:
            return ';'.join(map(str,own_list))
        return "No owners"


    def __str__(self) -> str:
        string = f"{self.app_id},{self.display_name},{self.print_owners()},{self.has_active_secrets()}"
        return string

    @staticmethod
    def get_header() -> str:
        string = "app_id,self.display_name,app_owners,has_active_secrets"
        return string


def print_csv(items: list):

    print(items[0].get_header())

    for item in items:
        print(item)

def get_apps() -> dict:
    return call_graph_api("https://graph.microsoft.com/v1.0/applications")["value"]

def get_owners(obj_id) -> dict:
    url = f"https://graph.microsoft.com/v1.0/applications/{obj_id}/owners"
    return call_graph_api(url)


def create_owners(obj_id: str) -> List[Owner]:
    json_dict = get_owners(obj_id)

    owner_list = []
    for owner in json_dict["value"]:
        upn = owner["userPrincipalName"]


        owner_obj = None

        for own in owners:
            if own.upn == upn:
                owner_obj = own
                break

        if owner_obj == None:
            owner_obj = Owner(upn)
        
        owners.append(owner_obj)
        owner_list.append(owner_obj)

    return owner_list

def create_permissions(permission_dict: dict) -> List[Permission]:

    perm_list = []
    resource_app_id = permission_dict["resourceAppId"]
    for perm in permission_dict["resourceAccess"]:
        perm_id = perm["id"]
        perm_scope = perm["type"]
        permission = Permission(resource_app_id, perm_id, perm_scope)
        perm_list.append(permission)

    return perm_list

def create_secret(secret_dict: dict) -> Secret:

    # The time format are not the same. Some uses a fraction of a second
    # I dont bother to create a regex or to remove the fraction which would be cleaner
    if "." in secret_dict["endDateTime"]:
        end_date = datetime.datetime.strptime( secret_dict["endDateTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        end_date = datetime.datetime.strptime( secret_dict["endDateTime"], "%Y-%m-%dT%H:%M:%SZ")
    secret = Secret(secret_dict["displayName"], end_date)

    return secret

def create_app(app_dict: dict, app_id: str, obj_id: str, app_display_name: str) -> App:

    app_obj = App(app_id, obj_id, app_display_name)

    owners = create_owners(obj_id)
    app_obj.add_owners(owners)

    if len(app_dict["requiredResourceAccess"]) != 0:
        # resource_app_id = app_dict["requiredResourceAccess"][0]["resourceAppId"]
        # for perm in app_dict["requiredResourceAccess"][0]["resourceAccess"]:
        #     perm_id = perm["id"]
        #     perm_scope = perm["type"]
        #     permission = Permission(resource_app_id, perm_id, perm_scope)
        #     app_obj.add_permission(permission)
        permissions = create_permissions(app_dict["requiredResourceAccess"][0])
        app_obj.add_permissions(permissions)

    for password in app_dict["passwordCredentials"]:
        secret = create_secret(password)
        app_obj.add_password(secret)

        for password in app_dict["keyCredentials"]:
            secret = create_secret(password)
            app_obj.add_key(secret)

    return app_obj

def call_graph_api(url) -> dict:
    headers = {"Authorization": f"Bearer {args.token}"}
    resp = requests.get(url, headers=headers)
    resp_dict = resp.json()
    return resp_dict


parser = argparse.ArgumentParser("parser")
parser.add_argument("-t", "--token", help="Access Token for Microsoft Graph API", required=True)

option_group = parser.add_mutually_exclusive_group()
option_group.add_argument("-a", "--apps", help="Print Application information", required=False, action='store_true')
option_group.add_argument("-o", "--owners", help="Print Application owner information", required=False, action='store_true')
option_group.add_argument("-ap", "--appPermissions", help="Print Application permission information", required=False, action='store_true')
args = parser.parse_args()

apps = []
owners = []


if __name__ == "__main__":

    resp_dict = get_apps()

    if args.apps:
        resp_dict = get_apps()

        for item in resp_dict:
            app_obj = create_app(item, item["appId"], item["id"], item["displayName"])
            apps.append(app_obj)

        print_csv(apps)
    # TODO add printing of owners with permissions. And apps with permissions on each line