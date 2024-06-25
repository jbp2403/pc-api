import requests
import argparse
import sys
import json
from getpass import getpass
import datetime
from time import sleep

def login_saas(base_url, access_key, secret_key):
    url = f"https://{base_url}/login"
    # logger.info(f"API URL: {url}")
    payload = json.dumps({"username": access_key, "password": secret_key})
    headers = {"content-type": "application/json; charset=UTF-8"}
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except Exception as e:
        # logger.info(f"Error in login_saas: {e}")
        return None

    return response.json().get("token")

def list_access_keys(url, token):
    endpoint = f"https://{url}/access_keys"
    payload = {}
    headers = {'Accept':'application/json','x-redlock-auth':token}

    try:
        response = requests.get(endpoint, headers=headers, data=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print(f"{err}")
        sys.exit('Terminated')

    return response.json()

def create_access_keys(url, token, valid_to, identity):
    endpoint = f"https://{url}/access_keys"
    keyName = gen_key_name(identity)
    expiration = expire_time(valid_to)
    print(f"Expiration timestamp: {expiration}")
    print(f"Expiration: {datetime.datetime.fromtimestamp((expiration/1000), tz=datetime.timezone.utc)}")
    payload = json.dumps({"name":keyName, "expiresOn": expiration})
    headers = {'Content-Type':'application/json','x-redlock-auth':token}

    try:
        response = requests.post(endpoint, headers=headers, data=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print(f"{err}")
        print_raw_request(response.request)
        sys.exit('Terminated')

    return response.json()

def gen_key_name(identity):
    #separate components if email, or just return the value
    name = identity.split('@')[0]
    #append a datestamp to the value
    current_date = datetime.datetime.now()
    formattedDate = current_date.strftime('%Y%m%d')
    return "-".join([name,formattedDate])

def expire_time(days):
    print(f"Days: {days}")
    current_time = datetime.datetime.now(datetime.UTC)
    print(f"current_time: {current_time}")
    time_duration = datetime.timedelta(days=days)
    future_time = (current_time + time_duration).timestamp() * 1000
    return int(future_time)

def print_raw_request(request):
    """
    Prints the raw HTTP request in a readable format.
    """
    print(f"==================REQUEST================")
    request = request.prepare() if isinstance(request, requests.Request) else request
    headers = '\r\n'.join(f'{k}: {v}' for k, v in request.headers.items())
    body = '' if request.body is None else request.body.decode() if isinstance(request.body, bytes) else request.body
    print(f'{request.method} {request.path_url} HTTP/1.1\r\n{headers}\r\n\r\n{body}')

def main():
    default_url = "api.prismacloud.io"
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', '-u', type=str, default=default_url, help="Enter the PC API URL")
    parser.add_argument('--identity', '-i', type=str, required=True, help="Enter your identity/keyID")
    parser.add_argument('--secret-key', '-s', type=str, help="Enter your password/secret")
    parser.add_argument('--CreateKeys', action="store_true", help="Set flag to generate access keys for user")
    parser.add_argument('--expiry', '-e', type=int, required=False, default=180, help="Length of time (in days) before key expires.")

    args = parser.parse_args()
    key = args.secret_key if args.secret_key else getpass('Enter your key/password: ')

    url = args.url
    identity = args.identity

    token = login_saas(url, identity, key)
    if args.CreateKeys:
        print(f"Creating access keys for {identity}")
        creds = create_access_keys(url, token, args.expiry, identity)
        #Pause for a few seconds to allow for system sync
        print(f"KeyID: {creds['id']}")
        print(f"SecretKey: {creds['secretKey']}")
        sleep(5)
    
    access_keys = list_access_keys(url, token)

    print(json.dumps(access_keys))


if __name__ == "__main__":
    main()