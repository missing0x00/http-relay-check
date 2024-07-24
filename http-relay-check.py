#!/usr/bin/env python3
import argparse
import urllib3
import requests
from requests_ntlm import HttpNtlmAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

global args


def auth_cbt(url, domain, username, password, cbt):
    session = requests.Session()
    session.auth = HttpNtlmAuth(f'{domain}\\{username}', password, send_cbt=cbt)
    try:
        response = session.get(url, verify=False)
        return response
    except Exception as e:
        print(f'Request Failed: {e}')
        exit()


def main():
    global args

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('url', help='Target URL', type=str)
    parser.add_argument('-u', dest='username', help='Username', type=str, required=True)
    parser.add_argument('-d', dest='domain', help='AD Domain', type=str, required=True)
    parser.add_argument('-p', dest='password', help='Password', type=str, required=True)

    try:
        args = parser.parse_args()

        print('Requesting page without authentication')
        unauth_response = requests.get(args.url, verify=False)
        if unauth_response.ok:
            print(f'[!] Unauthenticated request succeeded! Status code: {unauth_response.status_code}')
            print(f'[!] Target URL does not appear to require authentication. Exiting.')
            exit()
        else:
            print(f'[*] Authentication required, continuing. Status code: {unauth_response.status_code}')

        print('Attempting authentication WITH CBT')
        cbt_response = auth_cbt(args.url, args.domain, args.username, args.password, True)

        if cbt_response.ok:
            print(f'[*] Authentication with CBT succeeded. Status code: {cbt_response.status_code}')
        else:
            print(f'[!] Authentication with CBT failed! Status code: {cbt_response.status_code}')
            print('[!] Verify credentials and target URL. Exiting to avoid account lockout.')
            exit()

        print('Attempting authentication WITHOUT CBT')
        nocbt_response = auth_cbt(args.url, args.domain, args.username, args.password, False)

        if nocbt_response.ok:
            print(f'[+] Authentication without CBT succeeded: CBT not required! Status code: {nocbt_response.status_code}')
            print(f'[+] {args.url} may be vulnerable to NTLM relay attacks')
        else:
            print(f'[-] Authentication without CBT failed: CBT required! Status code: {nocbt_response.status_code}')


    except Exception as e:
        print(e)
        exit(0)


if __name__ == "__main__":
    main()