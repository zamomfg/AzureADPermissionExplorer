import requests
import os
import json
import datetime
import argparse


# path = os.path.join(os.path.expanduser('~'), ".azure/msal_token_cache.json" )

# # if os.name != 'nt':
# print(path)
# with open(path, "r") as inputFile:
#     tokenFile = inputFile.read()
#     jsonTokens= json.loads(tokenFile)


parser = argparse.ArgumentParser("parser")
parser.add_argument("-t", "--token", help="Access Token for Microsoft Graph API", required=True)
args = parser.parse_args()

headers = {"Authorization": f"Bearer {args.token}"}
resp = requests.get("https://graph.microsoft.com/v1.0/applications", headers=headers)

resp_dict = resp.json()

print(resp_dict.get("value"))