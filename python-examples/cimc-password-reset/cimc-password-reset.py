__license__ = """
Copyright (c) 2025 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import requests
from requests.auth import HTTPBasicAuth
import argparse
import json

# Disable warnings for self-signed certificates (optional)
requests.packages.urllib3.disable_warnings()

# Color Coding for screen output.
class color:
    GREEN =  "\033[32m"
    RED =    "\033[31m"
    YELLOW = "\033[33m"
    NORMAL = "\033[0m"

def WRITE_STATUS(message:str, event_status:str="INFO"):
    if event_status=="INFO":
        print(f"[{color.GREEN} INFO {color.NORMAL}] {message}")
    elif event_status=="WARN":
        print(f"[{color.YELLOW} WARN {color.NORMAL}] {message}")
    elif event_status=="FAIL":
       print(f"[{color.RED} FAIL {color.NORMAL}] {message}")
       print("Exiting Script")
       quit()

def CALL_REDFISH(api_path, payload=None):
    if args.verbose > 0: WRITE_STATUS(message="Starting REDFISH API Call")
    if args.verbose > 0: WRITE_STATUS(message=f"  CIMC IP:  {args.cimc_ip}")
    if args.verbose > 0: WRITE_STATUS(message=f"  API Path: {api_path}")
    headers = {"Content-Type": "application/json"}
    url = f"https://{args.cimc_ip}{api_path}"
    if payload == None:
        # This section is just used for developement. Should never run in the real world...
        if args.verbose > 0: WRITE_STATUS(message=' Getting content from API path - No change called for')
        response = requests.get(url, auth=HTTPBasicAuth(args.username, args.password), headers=headers, verify=False)
        if response.status_code != 200:
            WRITE_STATUS(message=f"Failed to connect to the server with error code {response.status_code}",event_status="FAIL")
        else:
            if args.verbose > 0: WRITE_STATUS(message='Returned 200, successful request')
            if args.verbose > 1: print(f"{json.dumps(response.json(),indent=4)}")
        return response
    else:
        if args.verbose > 0: WRITE_STATUS(message=' Password Change is being attempted')
        response = requests.patch(url, auth=HTTPBasicAuth(args.username, args.password), json=payload, headers=headers, verify=False)
        if response.status_code != 200:
            WRITE_STATUS(message=f"Failed to connect to the server with error code {response.status_code}\n{response.text}",event_status="FAIL")
        else:
            if args.verbose > 0: WRITE_STATUS(message='Returned 200, successful password change')
            if args.verbose > 1: print(f"{json.dumps(response.json(),indent=4)}")
            return response

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Change CIMC password using Redfish API")
    parser.add_argument("--cimc_ip",       required=True,  type=str,                     help="CIMC IP address")
    parser.add_argument("--username",      required=False, type=str, default='admin',    help="Current username")
    parser.add_argument("--password",      required=False, type=str, default='password', help="Current password")
    parser.add_argument("-v", "--verbose", required=False,           default=0,          help="Verbose Logging",     action='count' )
    parser.add_argument("--new_password",  required=True,  type=str,                     help="New password to set")
    args = parser.parse_args()


    payload = {
        "Password": args.new_password
    }


    password_change_result=CALL_REDFISH(api_path=f"/redfish/v1/AccountService/Accounts/1", payload=payload)
